//! Workspace policy (`.ciphervault/policy.toml`): schema, hand-rolled
//! TOML parsing, profile allow-list/allow-keys enforcement, and the
//! `policy init` / `policy check` commands.

use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WorkspacePolicy {
    pub(crate) sealed_mode: bool,
    pub(crate) default_no_net: Option<bool>,
    pub(crate) description: Option<String>,
    pub(crate) sandbox_read_paths: Vec<String>,
    pub(crate) profiles: BTreeMap<String, RunProfile>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RunProfile {
    pub(crate) description: Option<String>,
    pub(crate) commands: Vec<String>,
    pub(crate) allow_keys: Vec<String>,
    pub(crate) require_keys: Vec<String>,
    pub(crate) no_net: Option<bool>,
    pub(crate) proxy: Option<bool>,
    pub(crate) require_explicit_approval: Option<bool>,
    pub(crate) sandbox_read_paths: Vec<String>,
    pub(crate) upstreams: BTreeMap<String, String>,
}

pub(crate) fn load_workspace_policy(vault_dir: &Path) -> Result<Option<WorkspacePolicy>> {
    let policy_path = vault_dir.join("policy.toml");
    let raw = match std::fs::read_to_string(&policy_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| {
                format!("Failed to read workspace policy '{}'", policy_path.display())
            })
        }
    };
    let parsed = parse_workspace_policy(&raw).with_context(|| {
        format!(
            "Failed to parse workspace policy '{}'",
            policy_path.display()
        )
    })?;
    Ok(Some(parsed))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicySection {
    Vault,
    Profile(String),
    ProfileUpstreams(String),
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '#' => return &line[..idx],
                _ => {}
            }
        }
    }
    line
}

fn delimiter_balance(s: &str) -> Result<(i32, i32)> {
    let mut brackets = 0i32;
    let mut braces = 0i32;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for ch in s.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '[' => brackets += 1,
                ']' => brackets -= 1,
                '{' => braces += 1,
                '}' => braces -= 1,
                _ => {}
            }
        }
    }
    if in_double || in_single {
        bail!("unterminated string literal");
    }
    if brackets < 0 || braces < 0 {
        bail!("unexpected closing delimiter");
    }
    Ok((brackets, braces))
}

fn parse_toml_string(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => bail!("unsupported escape '\\{other}' in string"),
                    None => bail!("trailing backslash in string"),
                }
            } else {
                out.push(ch);
            }
        }
        return Ok(out);
    }
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        return Ok(s[1..s.len() - 1].to_string());
    }
    bail!("expected quoted string, got '{s}'")
}

fn parse_toml_bool(raw: &str) -> Result<bool> {
    match raw.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => bail!("expected boolean (true/false), got '{other}'"),
    }
}

fn split_top_level_commas(inner: &str) -> Result<Vec<String>> {
    let mut items = Vec::new();
    let mut start = 0usize;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut depth = 0i32;

    for (idx, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    let item = inner[start..idx].trim();
                    if !item.is_empty() {
                        items.push(item.to_string());
                    }
                    start = idx + 1;
                }
                _ => {}
            }
        }
    }
    let tail = inner[start..].trim();
    if !tail.is_empty() {
        items.push(tail.to_string());
    }
    Ok(items)
}

fn parse_toml_string_array(raw: &str) -> Result<Vec<String>> {
    let s = raw.trim();
    if !s.starts_with('[') || !s.ends_with(']') {
        bail!("expected array '[...]', got '{s}'");
    }
    let inner = s[1..s.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let items = split_top_level_commas(inner)?;
    items.into_iter().map(|item| parse_toml_string(&item)).collect()
}

fn split_key_value(line: &str) -> Result<(&str, &str)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            match ch {
                '\\' => escaped = true,
                '"' => in_double = false,
                _ => {}
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                '=' => return Ok((line[..idx].trim(), line[idx + 1..].trim())),
                _ => {}
            }
        }
    }
    bail!("expected 'key = value', got '{line}'")
}

fn parse_toml_key(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("empty key");
    }
    if s.starts_with('"') || s.starts_with('\'') {
        return parse_toml_string(s);
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Ok(s.to_string());
    }
    bail!("invalid key '{s}'")
}

fn parse_toml_inline_string_table(raw: &str) -> Result<BTreeMap<String, String>> {
    let s = raw.trim();
    if !s.starts_with('{') || !s.ends_with('}') {
        bail!("expected inline table '{{...}}', got '{s}'");
    }
    let inner = s[1..s.len() - 1].trim();
    let mut map = BTreeMap::new();
    if inner.is_empty() {
        return Ok(map);
    }
    for entry in split_top_level_commas(inner)? {
        let (k_raw, v_raw) = split_key_value(&entry)?;
        let key = parse_toml_key(k_raw)?;
        let val = parse_toml_string(v_raw)?;
        map.insert(key, val);
    }
    Ok(map)
}

fn parse_section_header(header: &str) -> Result<PolicySection> {
    let inner = header
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
        .context("malformed section header")?;
    if inner == "vault" {
        return Ok(PolicySection::Vault);
    }
    if let Some(rest) = inner.strip_prefix("profiles.") {
        let rest = rest.trim();
        if let Some(name_part) = rest.strip_suffix(".upstreams") {
            let name = parse_toml_key(name_part.trim())?;
            return Ok(PolicySection::ProfileUpstreams(name));
        }
        let name = parse_toml_key(rest)?;
        return Ok(PolicySection::Profile(name));
    }
    bail!("unknown policy section '[{inner}]'")
}

pub(crate) fn parse_workspace_policy(raw: &str) -> Result<WorkspacePolicy> {
    let mut policy = WorkspacePolicy::default();
    let mut current_section: Option<PolicySection> = None;
    let mut pending_stmt = String::new();
    let mut pending_start_line = 0usize;

    let mut logical_statements: Vec<(usize, String)> = Vec::new();
    for (idx, raw_line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let clean = strip_toml_comment(raw_line).trim();
        if clean.is_empty() && pending_stmt.is_empty() {
            continue;
        }
        if pending_stmt.is_empty() {
            pending_start_line = line_no;
            pending_stmt.push_str(clean);
        } else if !clean.is_empty() {
            pending_stmt.push(' ');
            pending_stmt.push_str(clean);
        }
        let (brackets, braces) = delimiter_balance(&pending_stmt)
            .with_context(|| format!("line {pending_start_line}"))?;
        if brackets == 0 && braces == 0 {
            let stmt = std::mem::take(&mut pending_stmt);
            logical_statements.push((pending_start_line, stmt));
        }
    }
    if !pending_stmt.is_empty() {
        bail!("line {pending_start_line}: unclosed '[' or '{{' in policy.toml");
    }

    for (line_no, stmt) in logical_statements {
        if stmt.starts_with('[') && stmt.ends_with(']') {
            let section =
                parse_section_header(&stmt).with_context(|| format!("line {line_no}"))?;
            match &section {
                PolicySection::Profile(name) | PolicySection::ProfileUpstreams(name) => {
                    policy.profiles.entry(name.clone()).or_default();
                }
                PolicySection::Vault => {}
            }
            current_section = Some(section);
            continue;
        }

        let section = current_section
            .as_ref()
            .with_context(|| format!("line {line_no}: key-value pair outside any [section]"))?;
        let (k_raw, v_raw) = split_key_value(&stmt).with_context(|| format!("line {line_no}"))?;
        let key = parse_toml_key(k_raw).with_context(|| format!("line {line_no}"))?;

        match section {
            PolicySection::Vault => match key.as_str() {
                "sealed_mode" => {
                    policy.sealed_mode =
                        parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?;
                }
                "default_no_net" => {
                    policy.default_no_net =
                        Some(parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?);
                }
                "description" => {
                    policy.description = Some(
                        parse_toml_string(v_raw).with_context(|| format!("line {line_no}"))?,
                    );
                }
                "sandbox_read_paths" => {
                    policy.sandbox_read_paths = parse_toml_string_array(v_raw)
                        .with_context(|| format!("line {line_no}"))?;
                }
                other => bail!("line {line_no}: unknown [vault] key '{other}'"),
            },
            PolicySection::Profile(name) => {
                let profile = policy.profiles.entry(name.clone()).or_default();
                match key.as_str() {
                    "description" => {
                        profile.description = Some(
                            parse_toml_string(v_raw).with_context(|| format!("line {line_no}"))?,
                        );
                    }
                    "commands" => {
                        profile.commands = parse_toml_string_array(v_raw)
                            .with_context(|| format!("line {line_no}"))?;
                    }
                    "allow_keys" => {
                        profile.allow_keys = parse_toml_string_array(v_raw)
                            .with_context(|| format!("line {line_no}"))?;
                    }
                    "require_keys" => {
                        profile.require_keys = parse_toml_string_array(v_raw)
                            .with_context(|| format!("line {line_no}"))?;
                    }
                    "no_net" => {
                        profile.no_net = Some(
                            parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?,
                        );
                    }
                    "proxy" => {
                        profile.proxy = Some(
                            parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?,
                        );
                    }
                    "require_explicit_approval" => {
                        profile.require_explicit_approval = Some(
                            parse_toml_bool(v_raw).with_context(|| format!("line {line_no}"))?,
                        );
                    }
                    "sandbox_read_paths" => {
                        profile.sandbox_read_paths = parse_toml_string_array(v_raw)
                            .with_context(|| format!("line {line_no}"))?;
                    }
                    "upstreams" => {
                        let parsed = parse_toml_inline_string_table(v_raw)
                            .with_context(|| format!("line {line_no}"))?;
                        profile.upstreams.extend(parsed);
                    }
                    other => bail!("line {line_no}: unknown [profiles.{name}] key '{other}'"),
                }
            }
            PolicySection::ProfileUpstreams(name) => {
                let profile = policy.profiles.entry(name.clone()).or_default();
                let val = parse_toml_string(v_raw).with_context(|| format!("line {line_no}"))?;
                profile.upstreams.insert(key, val);
            }
        }
    }

    Ok(policy)
}

fn command_matches_allowlist(cmd0: &str, allowed_commands: &[String]) -> bool {
    let cmd_trimmed = cmd0.trim();
    if cmd_trimmed.is_empty() {
        return false;
    }
    let basename = Path::new(cmd_trimmed)
        .file_name()
        .and_then(|s| s.to_str());

    allowed_commands.iter().any(|entry| {
        let allowed = entry.trim();
        if allowed.is_empty() {
            return false;
        }
        if allowed.contains('/') || allowed.contains('\\') {
            return cmd_trimmed == allowed || Path::new(cmd_trimmed) == Path::new(allowed);
        }
        if cmd_trimmed == allowed || basename == Some(allowed) {
            return true;
        }
        #[cfg(target_os = "windows")]
        if !allowed.to_ascii_lowercase().ends_with(".exe") {
            let exe_name = format!("{allowed}.exe");
            if basename.is_some_and(|b| b.eq_ignore_ascii_case(&exe_name)) {
                return true;
            }
        }
        false
    })
}

pub(crate) fn enforce_profile_command_allowlist(
    command: &[String],
    profile_name: &str,
    allowed_commands: &[String],
) -> Result<()> {
    if allowed_commands.is_empty() || command.is_empty() {
        return Ok(());
    }
    if !command_matches_allowlist(&command[0], allowed_commands) {
        bail!(
            "Command '{}' is not permitted by profile '{}' (allowed: {})",
            command[0],
            profile_name,
            allowed_commands.join(", ")
        );
    }
    Ok(())
}

pub(crate) fn merge_profile_allow_keys(
    caller: Option<Vec<String>>,
    profile_keys: &[String],
    profile_name: &str,
) -> Result<Option<Vec<String>>> {
    if profile_keys.is_empty() {
        return Ok(caller);
    }
    let mut profile_set = BTreeSet::new();
    for raw in profile_keys {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            profile_set.insert(validate_allow_pattern(trimmed)?);
        }
    }
    if profile_set.is_empty() {
        bail!("Profile '{profile_name}' has an empty allow_keys list");
    }
    match caller {
        Some(caller_vec) => {
            let caller_set = normalize_allow_keys(Some(&caller_vec))?
                .expect("normalize_allow_keys returns Some for Some input");
            let intersected: Vec<String> = caller_set
                .into_iter()
                .filter(|c| {
                    if c.contains('*') {
                        profile_set.iter().any(|p| patterns_can_overlap(c, p))
                    } else {
                        profile_set.iter().any(|p| key_matches_pattern(c, p))
                    }
                })
                .collect();
            if intersected.is_empty() {
                bail!(
                    "--allow-keys has no keys permitted by profile '{profile_name}'"
                );
            }
            Ok(Some(intersected))
        }
        None => Ok(Some(profile_set.into_iter().collect())),
    }
}

pub(crate) fn build_profile_allow_keys_filter(
    caller: Option<Vec<String>>,
    profile_keys: &[String],
    profile_require_keys: &[String],
    profile_name: &str,
) -> Result<AllowKeysFilter> {
    let mut require_keys = Vec::new();
    for raw in profile_require_keys {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains('*') {
            bail!(
                "Profile '{profile_name}' require_keys entry '{trimmed}' cannot contain '*' wildcards"
            );
        }
        validate_allow_pattern(trimmed)?;
        if !require_keys.iter().any(|k| k == trimmed) {
            require_keys.push(trimmed.to_string());
        }
    }

    if profile_keys.is_empty() {
        let cli_patterns = match caller {
            Some(v) => Some(
                normalize_allow_keys(Some(&v))?
                    .expect("normalize_allow_keys returns Some for Some input")
                    .into_iter()
                    .collect(),
            ),
            None => None,
        };
        return Ok(AllowKeysFilter {
            profile_patterns: None,
            cli_patterns,
            require_keys,
            profile_name: Some(profile_name.to_string()),
        });
    }

    let mut profile_set = BTreeSet::new();
    for raw in profile_keys {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            profile_set.insert(validate_allow_pattern(trimmed)?);
        }
    }
    if profile_set.is_empty() {
        bail!("Profile '{profile_name}' has an empty allow_keys list");
    }

    let (profile_patterns, cli_patterns) = match caller {
        None => (Some(profile_set.into_iter().collect()), None),
        Some(caller_vec) => {
            let caller_set = normalize_allow_keys(Some(&caller_vec))?
                .expect("normalize_allow_keys returns Some for Some input");
            if caller_set == profile_set {
                // Caller echoed the exact profile upper bound: retain profile upper-bound semantics.
                (Some(profile_set.into_iter().collect()), None)
            } else {
                let narrowed =
                    merge_profile_allow_keys(Some(caller_vec), profile_keys, profile_name)?;
                (Some(profile_set.into_iter().collect()), narrowed)
            }
        }
    };

    Ok(AllowKeysFilter {
        profile_patterns,
        cli_patterns,
        require_keys,
        profile_name: Some(profile_name.to_string()),
    })
}

pub(crate) fn starter_policy_toml(sealed_mode: bool) -> String {
    format!(
        r#"[vault]
sealed_mode = {sealed_mode}
default_no_net = true
description = "Workspace secret execution policy"

[profiles.test]
description = "Offline test runner with scoped test variables"
commands = ["pytest", "python", "npm", "npx", "node", "cargo", "vitest"]
allow_keys = ["DATABASE_URL", "REDIS_URL", "TEST_*"]
no_net = true

[profiles.llm_eval]
description = "LLM evaluation via loopback credential proxy"
commands = ["python", "node"]
allow_keys = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]
proxy = true
"#
    )
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct PolicyProfileReport {
    pub name: String,
    pub description: Option<String>,
    pub commands: Vec<String>,
    pub allow_keys: Vec<String>,
    pub require_keys: Vec<String>,
    pub no_net: Option<bool>,
    pub proxy: Option<bool>,
    pub require_explicit_approval: Option<bool>,
    pub sandbox_read_paths: Vec<String>,
    pub upstreams: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_vault_keys: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct PolicyCheckReport {
    pub success: bool,
    pub exists: bool,
    pub valid: bool,
    pub path: String,
    pub sealed_mode: bool,
    pub default_no_net: Option<bool>,
    pub description: Option<String>,
    pub sandbox_read_paths: Vec<String>,
    pub profiles: Vec<PolicyProfileReport>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub(crate) fn validate_workspace_policy(
    policy: &WorkspacePolicy,
    workspace_root: &Path,
    tracked_paths: &[String],
    snapshot_keys: Option<&BTreeSet<String>>,
) -> PolicyCheckReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let allow_loopback =
        std::env::var("CIPHERVAULT_ALLOW_LOOPBACK_UPSTREAM").as_deref() == Ok("1");

    for rel in &policy.sandbox_read_paths {
        match validate_sandbox_read_path(rel, workspace_root, tracked_paths) {
            Ok(full) => {
                if !full.exists() {
                    warnings.push(format!(
                        "[vault].sandbox_read_paths entry '{rel}' does not exist yet on disk"
                    ));
                }
            }
            Err(e) => errors.push(format!("[vault].sandbox_read_paths: {e}")),
        }
    }

    let mut profiles_out = Vec::new();
    for (name, prof) in &policy.profiles {
        let mut valid_allow_pats = Vec::new();
        for pat in &prof.allow_keys {
            match validate_allow_pattern(pat) {
                Ok(clean) => valid_allow_pats.push(clean),
                Err(e) => errors.push(format!("[profiles.{name}].allow_keys: {e}")),
            }
        }

        for req in &prof.require_keys {
            let trimmed = req.trim();
            if trimmed.is_empty() {
                errors.push(format!("[profiles.{name}].require_keys contains an empty key"));
                continue;
            }
            if trimmed.contains('*') {
                errors.push(format!(
                    "[profiles.{name}].require_keys entry '{trimmed}' cannot contain '*' wildcards"
                ));
                continue;
            }
            if let Err(e) = validate_allow_pattern(trimmed) {
                errors.push(format!("[profiles.{name}].require_keys: {e}"));
                continue;
            }
            if !valid_allow_pats.is_empty()
                && !valid_allow_pats
                    .iter()
                    .any(|p| key_matches_pattern(trimmed, p))
            {
                errors.push(format!(
                    "[profiles.{name}].require_keys '{trimmed}' is not matched by allow_keys"
                ));
            }
        }

        let proxy_active = prof.proxy == Some(true) || !prof.upstreams.is_empty();
        if prof.no_net == Some(true) && proxy_active {
            errors.push(format!(
                "[profiles.{name}] combines incompatible no_net = true with proxy/upstreams"
            ));
        }

        for (k, v) in &prof.upstreams {
            if let Err(e) =
                super::super::run_proxy::parse_proxy_upstream_spec(&format!("{k}={v}"), allow_loopback)
            {
                errors.push(format!("[profiles.{name}.upstreams] '{k}': {e}"));
            }
        }

        for rel in &prof.sandbox_read_paths {
            match validate_sandbox_read_path(rel, workspace_root, tracked_paths) {
                Ok(full) => {
                    if !full.exists() {
                        warnings.push(format!(
                            "[profiles.{name}].sandbox_read_paths entry '{rel}' does not exist yet on disk"
                        ));
                    }
                }
                Err(e) => errors.push(format!("[profiles.{name}].sandbox_read_paths: {e}")),
            }
        }

        let matched_vault_keys = snapshot_keys.map(|keys| {
            let matched: Vec<String> = if valid_allow_pats.is_empty() {
                keys.iter().cloned().collect()
            } else {
                keys.iter()
                    .filter(|k| valid_allow_pats.iter().any(|p| key_matches_pattern(k, p)))
                    .cloned()
                    .collect()
            };
            if !valid_allow_pats.is_empty() && matched.is_empty() {
                warnings.push(format!(
                    "[profiles.{name}] allow_keys currently matches 0 keys in active snapshot"
                ));
            }
            for req in &prof.require_keys {
                let r = req.trim();
                if !r.is_empty() && !matched.iter().any(|k| k == r) {
                    warnings.push(format!(
                        "[profiles.{name}] required key '{r}' is not present in active snapshot"
                    ));
                }
            }
            matched
        });

        profiles_out.push(PolicyProfileReport {
            name: name.clone(),
            description: prof.description.clone(),
            commands: prof.commands.clone(),
            allow_keys: prof.allow_keys.clone(),
            require_keys: prof.require_keys.clone(),
            no_net: prof.no_net,
            proxy: prof.proxy,
            require_explicit_approval: prof.require_explicit_approval,
            sandbox_read_paths: prof.sandbox_read_paths.clone(),
            upstreams: prof.upstreams.clone(),
            matched_vault_keys,
        });
    }

    let valid = errors.is_empty();
    PolicyCheckReport {
        success: valid,
        exists: true,
        valid,
        path: ".ciphervault/policy.toml".to_string(),
        sealed_mode: policy.sealed_mode,
        default_no_net: policy.default_no_net,
        description: policy.description.clone(),
        sandbox_read_paths: policy.sandbox_read_paths.clone(),
        profiles: profiles_out,
        errors,
        warnings,
    }
}

pub(crate) fn cmd_policy_init(sealed: bool, force: bool, json: bool) -> Result<()> {
    let _store = get_vault_store()?;
    let vault_dir = crate::util::get_vault_directory();
    let policy_path = vault_dir.join("policy.toml");
    if policy_path.exists() && !force {
        bail!(
            "'{}' already exists. Pass --force to overwrite it.",
            policy_path.display()
        );
    }
    let content = starter_policy_toml(sealed);
    // Sanity-parse our own template before writing.
    let parsed = parse_workspace_policy(&content)?;
    std::fs::write(&policy_path, content)
        .with_context(|| format!("writing '{}'", policy_path.display()))?;
    let profile_names: Vec<String> = parsed.profiles.keys().cloned().collect();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "path": ".ciphervault/policy.toml",
                "sealed_mode": sealed,
                "profiles": profile_names,
            }))?
        );
    } else {
        println!(
            "{} Created '{}' (sealed_mode={}, profiles: {})",
            "✓".green().bold(),
            policy_path.display(),
            sealed,
            profile_names.join(", ")
        );
    }
    Ok(())
}

pub(crate) fn cmd_policy_check(json: bool) -> Result<()> {
    let vault_dir = crate::util::get_vault_directory();
    let policy_path = vault_dir.join("policy.toml");
    if !policy_path.exists() {
        let report = PolicyCheckReport {
            success: true,
            exists: false,
            valid: true,
            path: ".ciphervault/policy.toml".to_string(),
            sealed_mode: false,
            default_no_net: None,
            description: None,
            sandbox_read_paths: Vec::new(),
            profiles: Vec::new(),
            errors: Vec::new(),
            warnings: vec![
                "No .ciphervault/policy.toml found; run 'ciphervault policy init' to create one."
                    .to_string(),
            ],
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("{}", report.warnings[0].yellow());
        }
        return Ok(());
    }

    let policy = match load_workspace_policy(&vault_dir) {
        Ok(Some(p)) => p,
        Ok(None) => unreachable!("policy_path existence already verified"),
        Err(err) => {
            if json {
                let report = PolicyCheckReport {
                    success: false,
                    exists: true,
                    valid: false,
                    path: ".ciphervault/policy.toml".to_string(),
                    sealed_mode: false,
                    default_no_net: None,
                    description: None,
                    sandbox_read_paths: Vec::new(),
                    profiles: Vec::new(),
                    errors: vec![format!("{err:#}")],
                    warnings: Vec::new(),
                };
                println!("{}", serde_json::to_string_pretty(&report)?);
                std::process::exit(1);
            }
            return Err(err);
        }
    };

    let workspace_root = crate::util::get_workspace_root()
        .or_else(|_| std::env::current_dir().map_err(anyhow::Error::from))?;
    let store_opt = get_vault_store().ok();
    let tracked_paths: Vec<String> = store_opt
        .as_ref()
        .and_then(|s| s.list_tracked_files().ok())
        .unwrap_or_default()
        .into_iter()
        .map(|(p, _)| p.to_string_lossy().replace('\\', "/"))
        .collect();

    // Collect key names only (zeroizing plaintext immediately) when a local head exists.
    let snapshot_keys: Option<BTreeSet<String>> = store_opt.as_ref().and_then(|store| {
        let mut bundle = load_local_snapshot_bundle_sync(store).ok()?;
        let mut keys = BTreeSet::new();
        for f in &mut bundle.files {
            let p = f.relative_path.replace('\\', "/");
            let name = p.rsplit('/').next().unwrap_or(&p);
            if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
                if let Ok(mut parsed) = dotenv::parse_dotenv_bytes(&f.plaintext) {
                    for (k, _) in &parsed {
                        keys.insert(k.clone());
                    }
                    dotenv::zeroize_env_pairs(&mut parsed);
                }
            }
            f.plaintext.zeroize();
        }
        Some(keys)
    });

    let report = validate_workspace_policy(
        &policy,
        &workspace_root,
        &tracked_paths,
        snapshot_keys.as_ref(),
    );

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !report.valid {
            std::process::exit(1);
        }
        return Ok(());
    }

    if report.valid {
        println!(
            "{} Policy '{}' is valid ({} profile(s), sealed_mode={}).",
            "✓".green().bold(),
            report.path,
            report.profiles.len(),
            report.sealed_mode
        );
        for w in &report.warnings {
            println!("  {} {w}", "warning:".yellow().bold());
        }
        Ok(())
    } else {
        for e in &report.errors {
            eprintln!("  {} {e}", "error:".red().bold());
        }
        bail!(
            "Workspace policy '{}' failed validation with {} error(s)",
            report.path,
            report.errors.len()
        );
    }
}
