use super::*;

#[test]
fn allow_keys_filters_and_rejects_missing_or_empty() {
    let mut vars = vec![
        ("PORT".to_string(), Zeroizing::new("8080".to_string())),
        (
            "DB_PASS".to_string(),
            Zeroizing::new("val_db_99".to_string()),
        ),
        (
            "PROD_KEY".to_string(),
            Zeroizing::new("val_prod_88".to_string()),
        ),
    ];
    filter_loaded_vars_by_allow_keys(&mut vars, Some(&["PORT".to_string()])).unwrap();
    assert_eq!(vars.len(), 1);
    assert_eq!(vars[0].0, "PORT");

    let mut vars2 = vec![("PORT".to_string(), Zeroizing::new("8080".to_string()))];
    let err = filter_loaded_vars_by_allow_keys(&mut vars2, Some(&["MISSING".to_string()]))
        .unwrap_err();
    assert!(err.to_string().contains("MISSING"));
    assert!(vars2.is_empty());

    let empty_err = normalize_allow_keys(Some(&["  ".to_string()])).unwrap_err();
    assert!(empty_err.to_string().contains("at least one"));
}

#[test]
fn no_net_sandbox_fails_closed_when_unsupported() {
    #[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "windows")))]
    {
        let err = apply_no_net_sandbox("echo", &[], &["hi".to_string()]).unwrap_err();
        assert!(err.to_string().contains("--no-net"));
    }
    #[cfg(target_os = "windows")]
    {
        let ctx = windows_no_net::AppContainerContext::new().unwrap();
        ctx.ensure_winsta_desktop_access().unwrap();
        ctx.preflight().unwrap();

        // 1. Child executes cleanly inside AppContainer and receives injected env.
        let mut env_map = std::collections::BTreeMap::new();
        let sr = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        env_map.insert(
            "SYSTEMROOT".to_string(),
            ("SystemRoot".to_string(), Zeroizing::new(sr)),
        );
        env_map.insert(
            "CV_TEST_VAR".to_string(),
            ("CV_TEST_VAR".to_string(), Zeroizing::new("val123".to_string())),
        );
        let ok_args = vec!["/c".to_string(), "echo SANDBOX_OK_%CV_TEST_VAR%".to_string()];
        let (ok_code, ok_out, _) = ctx
            .execute("C:\\Windows\\System32\\cmd.exe", &ok_args, &env_map, false)
            .unwrap();
        assert_eq!(ok_code, 0);
        let stdout = String::from_utf8_lossy(&ok_out);
        assert!(stdout.contains("SANDBOX_OK_val123"), "stdout was: {stdout}");

        // 2. Outbound network connection is blocked by zero-capability AppContainer.
        let net_args = vec![
            "-s".to_string(),
            "--max-time".to_string(),
            "2".to_string(),
            "http://1.1.1.1".to_string(),
        ];
        let (net_code, _, _) = ctx
            .execute("C:\\Windows\\System32\\curl.exe", &net_args, &env_map, false)
            .unwrap();
        assert_ne!(net_code, 0, "outbound network should fail inside AppContainer");
    }
    #[cfg(target_vendor = "apple")]
    {
        if std::path::Path::new("/usr/bin/sandbox-exec").exists() {
            if let Ok((bin, args)) =
                apply_no_net_sandbox("/usr/bin/true", &[], &["arg1".to_string()])
            {
                assert_eq!(bin, "/usr/bin/sandbox-exec");
                assert!(args.iter().any(|a| a.contains("network-outbound")));
                assert_eq!(args.last().map(String::as_str), Some("arg1"));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok((bin, args)) = apply_no_net_sandbox("true", &[], &["arg1".to_string()]) {
            assert_eq!(bin, "unshare");
            assert!(args.contains(&"--net".to_string()) || args.contains(&"-n".to_string()));
            assert_eq!(args.last().map(String::as_str), Some("arg1"));
        }
    }
}

#[test]
fn windows_appcontainer_json_attaches_dll_hint_on_status_codes() {
    for code in [-1073741515i32, -1073741502i32] {
        let mut payload = serde_json::json!({
            "status": "failed",
            "exit_code": code,
            "no_net": true,
        });
        attach_appcontainer_hint(&mut payload, code);
        let hint = payload["appcontainer_hint"]
            .as_str()
            .expect("appcontainer_hint should be populated");
        assert!(hint.contains("S-1-15-2-1"));
        assert!(hint.contains("--proxy"));
    }

    let mut ok_payload = serde_json::json!({
        "status": "success",
        "exit_code": 0,
        "no_net": true,
    });
    attach_appcontainer_hint(&mut ok_payload, 0);
    assert!(ok_payload.get("appcontainer_hint").is_none());
}

#[test]
fn workspace_policy_parses_vault_and_profiles() {
    let dir = std::env::temp_dir().join(format!("cv-policy-test-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(load_workspace_policy(&dir).unwrap().is_none());

    let toml = r#"
# Workspace policy
[vault]
sealed_mode = true
default_no_net = true

[profiles.test]
commands = [
  "pytest",
  "python", # inline comment
]
allow_keys = ["DB_PASS", "API_KEY"]
no_net = true

[profiles.ai]
commands = ["node"]
allow_keys = ["OPENAI_API_KEY"]
proxy = true
upstreams = { OPENAI_API_KEY = "https://api.openai.com#v1" }

[profiles."staging-deploy".upstreams]
STRIPE_KEY = "https://api.stripe.com"
"#;
    std::fs::write(dir.join("policy.toml"), toml).unwrap();

    let policy = load_workspace_policy(&dir).unwrap().unwrap();
    assert!(policy.sealed_mode);
    assert_eq!(policy.default_no_net, Some(true));

    let test_prof = &policy.profiles["test"];
    assert_eq!(test_prof.commands, vec!["pytest", "python"]);
    assert_eq!(test_prof.allow_keys, vec!["DB_PASS", "API_KEY"]);
    assert_eq!(test_prof.no_net, Some(true));
    assert_eq!(test_prof.proxy, None);
    assert!(test_prof.upstreams.is_empty());

    let ai_prof = &policy.profiles["ai"];
    assert_eq!(ai_prof.commands, vec!["node"]);
    assert_eq!(ai_prof.allow_keys, vec!["OPENAI_API_KEY"]);
    assert_eq!(ai_prof.proxy, Some(true));
    assert_eq!(
        ai_prof.upstreams.get("OPENAI_API_KEY").map(String::as_str),
        Some("https://api.openai.com#v1")
    );

    let staging = &policy.profiles["staging-deploy"];
    assert_eq!(
        staging.upstreams.get("STRIPE_KEY").map(String::as_str),
        Some("https://api.stripe.com")
    );

    // Unknown keys fail closed
    std::fs::write(dir.join("policy.toml"), "[vault]\nunknown_key = true\n").unwrap();
    assert!(load_workspace_policy(&dir).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn profile_command_allowlist_and_allow_keys_intersection() {
    let allowed = vec!["pytest".to_string(), "/usr/bin/python3".to_string()];
    assert!(enforce_profile_command_allowlist(
        &["pytest".to_string(), "-q".to_string()],
        "test",
        &allowed
    )
    .is_ok());
    assert!(enforce_profile_command_allowlist(
        &["/venv/bin/pytest".to_string()],
        "test",
        &allowed
    )
    .is_ok());
    assert!(enforce_profile_command_allowlist(
        &["/usr/bin/python3".to_string()],
        "test",
        &allowed
    )
    .is_ok());
    // Path-qualified allowlist entry must not match an arbitrary directory's python3
    assert!(enforce_profile_command_allowlist(
        &["/tmp/evil/python3".to_string()],
        "test",
        &allowed
    )
    .is_err());
    assert!(enforce_profile_command_allowlist(
        &["curl".to_string()],
        "test",
        &allowed
    )
    .is_err());

    let profile_keys = vec!["DB_PASS".to_string(), "API_KEY".to_string()];
    // No caller allow_keys -> uses profile keys
    let merged_none = merge_profile_allow_keys(None, &profile_keys, "test")
        .unwrap()
        .unwrap();
    assert_eq!(merged_none, vec!["API_KEY", "DB_PASS"]);

    // Caller narrows -> intersection
    let narrowed = merge_profile_allow_keys(
        Some(vec!["API_KEY".to_string(), "ADMIN_TOKEN".to_string()]),
        &profile_keys,
        "test",
    )
    .unwrap()
    .unwrap();
    assert_eq!(narrowed, vec!["API_KEY"]);

    // Disjoint -> error (never widens)
    assert!(merge_profile_allow_keys(
        Some(vec!["ADMIN_TOKEN".to_string()]),
        &profile_keys,
        "test",
    )
    .is_err());
}

#[test]
fn wildcard_glob_matching_and_overlap_detection() {
    assert!(key_matches_pattern("TEST_DB_URL", "TEST_*"));
    assert!(key_matches_pattern("TEST_", "TEST_*"));
    assert!(!key_matches_pattern("TES_DB", "TEST_*"));
    assert!(key_matches_pattern("OPENAI_API_KEY", "*_API_KEY"));
    assert!(key_matches_pattern("APP_PROD_SECRET", "APP_*_SECRET"));
    assert!(key_matches_pattern("ANY_KEY", "*"));
    assert!(!key_matches_pattern("OPENAI_API_KEY_2", "OPENAI_API_KEY"));

    assert!(patterns_can_overlap("TEST_*", "TEST_FOO"));
    assert!(patterns_can_overlap("TEST_*", "*_KEY"));
    assert!(patterns_can_overlap("TEST_DB_*", "TEST_*"));
    assert!(!patterns_can_overlap("PROD_*", "TEST_*"));
    assert!(!patterns_can_overlap("A*B", "A*C"));
    assert!(patterns_can_overlap("*A", "B*"));
}

#[test]
fn profile_upper_bound_wildcards_optional_and_require_keys() {
    // 1. Starter `test` profile with `TEST_*` wildcard & optional `REDIS_URL`
    let test_allow = vec![
        "DATABASE_URL".to_string(),
        "REDIS_URL".to_string(),
        "TEST_*".to_string(),
    ];
    let filter = build_profile_allow_keys_filter(None, &test_allow, &[], "test").unwrap();
    let mut vars = vec![
        ("DATABASE_URL".to_string(), Zeroizing::new("pg://db".to_string())),
        ("TEST_TOKEN".to_string(), Zeroizing::new("t1".to_string())),
        ("TEST_SECRET".to_string(), Zeroizing::new("t2".to_string())),
        ("PROD_STRIPE_KEY".to_string(), Zeroizing::new("sk_live_x".to_string())),
    ];
    filter_loaded_vars_with_policy(&mut vars, &filter).unwrap();
    let names: Vec<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, vec!["DATABASE_URL", "TEST_TOKEN", "TEST_SECRET"]);

    // 2. Starter `llm_eval` profile with only 1 of 3 provider keys present succeeds
    let llm_allow = vec![
        "OPENAI_API_KEY".to_string(),
        "ANTHROPIC_API_KEY".to_string(),
        "GEMINI_API_KEY".to_string(),
    ];
    let llm_filter =
        build_profile_allow_keys_filter(None, &llm_allow, &[], "llm_eval").unwrap();
    let mut llm_vars = vec![
        ("OPENAI_API_KEY".to_string(), Zeroizing::new("sk-123".to_string())),
        ("DATABASE_URL".to_string(), Zeroizing::new("pg://db".to_string())),
    ];
    filter_loaded_vars_with_policy(&mut llm_vars, &llm_filter).unwrap();
    assert_eq!(llm_vars.len(), 1);
    assert_eq!(llm_vars[0].0, "OPENAI_API_KEY");

    // 3. Profile upper-bound errors when ZERO keys match in vault
    let mut empty_match_vars = vec![(
        "UNRELATED_KEY".to_string(),
        Zeroizing::new("val".to_string()),
    )];
    let err = filter_loaded_vars_with_policy(&mut empty_match_vars, &llm_filter).unwrap_err();
    assert!(err.to_string().contains("matched 0 variables"));
    assert!(empty_match_vars.is_empty());

    // 4. Explicit CLI --allow-keys narrows against wildcard profile & requires exact keys
    let cli_narrow_ok = build_profile_allow_keys_filter(
        Some(vec!["TEST_TOKEN".to_string()]),
        &test_allow,
        &[],
        "test",
    )
    .unwrap();
    let mut vars_narrow = vec![
        ("DATABASE_URL".to_string(), Zeroizing::new("pg://db".to_string())),
        ("TEST_TOKEN".to_string(), Zeroizing::new("t1".to_string())),
        ("TEST_OTHER".to_string(), Zeroizing::new("t2".to_string())),
    ];
    filter_loaded_vars_with_policy(&mut vars_narrow, &cli_narrow_ok).unwrap();
    assert_eq!(vars_narrow.len(), 1);
    assert_eq!(vars_narrow[0].0, "TEST_TOKEN");

    let cli_narrow_missing = build_profile_allow_keys_filter(
        Some(vec!["TEST_MISSING".to_string()]),
        &test_allow,
        &[],
        "test",
    )
    .unwrap();
    let mut vars_missing = vec![("TEST_TOKEN".to_string(), Zeroizing::new("t1".to_string()))];
    let miss_err =
        filter_loaded_vars_with_policy(&mut vars_missing, &cli_narrow_missing).unwrap_err();
    assert!(miss_err.to_string().contains("TEST_MISSING"));
    assert!(vars_missing.is_empty());

    // 5. CLI wildcard NEVER widens beyond profile allow_keys
    let narrow_prof = vec!["TEST_A".to_string(), "TEST_B".to_string()];
    let cli_wild = build_profile_allow_keys_filter(
        Some(vec!["TEST_*".to_string()]),
        &narrow_prof,
        &[],
        "narrow",
    )
    .unwrap();
    let mut wild_vars = vec![
        ("TEST_A".to_string(), Zeroizing::new("a".to_string())),
        (
            "TEST_SECRET_OUTSIDE_PROFILE".to_string(),
            Zeroizing::new("leak".to_string()),
        ),
    ];
    filter_loaded_vars_with_policy(&mut wild_vars, &cli_wild).unwrap();
    assert_eq!(wild_vars.len(), 1);
    assert_eq!(wild_vars[0].0, "TEST_A");

    // 6. require_keys fails when missing from vault or excluded by CLI narrowing
    let req_filter = build_profile_allow_keys_filter(
        None,
        &test_allow,
        &["DATABASE_URL".to_string()],
        "test",
    )
    .unwrap();
    let mut missing_req_vars = vec![("TEST_A".to_string(), Zeroizing::new("a".to_string()))];
    let req_err =
        filter_loaded_vars_with_policy(&mut missing_req_vars, &req_filter).unwrap_err();
    assert!(req_err.to_string().contains("require_keys"));
    assert!(req_err.to_string().contains("DATABASE_URL"));
    assert!(missing_req_vars.is_empty());

    let req_excluded_filter = build_profile_allow_keys_filter(
        Some(vec!["TEST_A".to_string()]),
        &test_allow,
        &["DATABASE_URL".to_string()],
        "test",
    )
    .unwrap();
    let mut both_vars = vec![
        ("DATABASE_URL".to_string(), Zeroizing::new("pg://db".to_string())),
        ("TEST_A".to_string(), Zeroizing::new("a".to_string())),
    ];
    assert!(filter_loaded_vars_with_policy(&mut both_vars, &req_excluded_filter).is_err());
    assert!(both_vars.is_empty());
}

#[test]
fn workspace_policy_parses_extended_fields_and_validates_sandbox_paths() {
    let dir = std::env::temp_dir().join(format!("cv-policy-ext-{}", rand::random::<u64>()));
    std::fs::create_dir_all(dir.join(".venv")).unwrap();
    std::fs::create_dir_all(dir.join("node_modules")).unwrap();
    std::fs::create_dir_all(dir.join("config")).unwrap();

    let toml = r#"
[vault]
sealed_mode = true
default_no_net = true
description = "My repo policy"
sandbox_read_paths = [".venv", "node_modules"]

[profiles.test]
description = "Offline pytest profile"
commands = ["pytest", "python"]
allow_keys = ["DATABASE_URL", "TEST_*"]
require_keys = ["DATABASE_URL"]
no_net = true
require_explicit_approval = false
sandbox_read_paths = [".venv"]

[profiles.deploy]
description = "Production deploy"
commands = ["node"]
allow_keys = ["STRIPE_SECRET_KEY"]
proxy = true
require_explicit_approval = true
"#;
    let policy = parse_workspace_policy(toml).unwrap();
    assert_eq!(policy.description.as_deref(), Some("My repo policy"));
    assert_eq!(policy.sandbox_read_paths, vec![".venv", "node_modules"]);
    let test_p = &policy.profiles["test"];
    assert_eq!(test_p.description.as_deref(), Some("Offline pytest profile"));
    assert_eq!(test_p.require_keys, vec!["DATABASE_URL"]);
    assert_eq!(test_p.require_explicit_approval, Some(false));
    assert_eq!(test_p.sandbox_read_paths, vec![".venv"]);
    let deploy_p = &policy.profiles["deploy"];
    assert_eq!(deploy_p.require_explicit_approval, Some(true));

    let tracked = vec![".env".to_string(), "config/prod.env".to_string()];
    let snap_keys: BTreeSet<String> = ["DATABASE_URL", "TEST_FOO", "STRIPE_SECRET_KEY"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let report = validate_workspace_policy(&policy, &dir, &tracked, Some(&snap_keys));
    assert!(report.valid, "errors: {:?}", report.errors);
    assert!(report.errors.is_empty());

    // Safe sandbox_read_paths accepted; secret/vault/tracked/parent-of-tracked/traversal rejected
    assert!(validate_sandbox_read_path(".venv", &dir, &tracked).is_ok());
    assert!(validate_sandbox_read_path("node_modules", &dir, &tracked).is_ok());
    assert!(validate_sandbox_read_path("../escape", &dir, &tracked).is_err());
    assert!(validate_sandbox_read_path("/etc", &dir, &tracked).is_err());
    assert!(validate_sandbox_read_path(".ciphervault", &dir, &tracked).is_err());
    assert!(validate_sandbox_read_path(".ciphervault/policy.toml", &dir, &tracked).is_err());
    assert!(validate_sandbox_read_path(".env", &dir, &tracked).is_err());
    assert!(validate_sandbox_read_path("config", &dir, &tracked).is_err());
    assert!(validate_sandbox_read_path("config/prod.env", &dir, &tracked).is_err());

    // Starter policy template must always parse & validate cleanly
    let starter = parse_workspace_policy(&starter_policy_toml(true)).unwrap();
    let starter_rep = validate_workspace_policy(&starter, &dir, &tracked, None);
    assert!(starter_rep.valid, "starter errors: {:?}", starter_rep.errors);

    // Policy check flags incompatible no_net + proxy and require_keys outside allow_keys
    let bad_toml = r#"
[profiles.broken]
allow_keys = ["TEST_*"]
require_keys = ["DATABASE_URL"]
no_net = true
proxy = true
"#;
    let bad_policy = parse_workspace_policy(bad_toml).unwrap();
    let bad_rep = validate_workspace_policy(&bad_policy, &dir, &tracked, None);
    assert!(!bad_rep.valid);
    assert!(bad_rep.errors.len() >= 2);

    // Unknown keys still fail closed
    assert!(parse_workspace_policy("[profiles.x]\nbogus_key = 1\n").is_err());

    let _ = std::fs::remove_dir_all(&dir);
}
