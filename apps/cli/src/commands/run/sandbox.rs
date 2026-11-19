//! `--no-net` sandboxing: workspace-confined `sandbox_read_paths`
//! validation plus the per-OS network-isolation wrappers (Linux
//! `unshare`, macOS `sandbox-exec`, Windows AppContainer).

use super::*;

/// Validates a relative `sandbox_read_paths` entry from `policy.toml` so AppContainer
/// read-only grants can never escape the workspace or touch `.ciphervault`/secret files.
pub(crate) fn validate_sandbox_read_path(
    rel_raw: &str,
    workspace_root: &Path,
    tracked_paths: &[String],
) -> Result<std::path::PathBuf> {
    let trimmed = rel_raw.trim();
    if trimmed.is_empty() {
        bail!("sandbox_read_paths entry cannot be empty");
    }
    if trimmed.contains('\0')
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.contains(':')
    {
        bail!("sandbox_read_paths entry '{trimmed}' must be a relative path inside the workspace");
    }
    let mut norm = trimmed.replace('\\', "/");
    while let Some(stripped) = norm.strip_prefix("./") {
        norm = stripped.to_string();
    }
    norm = norm.trim_end_matches('/').to_string();
    if norm.is_empty() || norm == "." {
        bail!("sandbox_read_paths entry '{trimmed}' cannot target the workspace root '.'");
    }
    ciphervault_snapshot::validate_safe_relative_path(&norm)
        .map_err(|e| anyhow::anyhow!("Invalid sandbox_read_paths entry '{trimmed}': {e}"))?;

    if crate::commands::agent_hooks::is_protected_vault_config_path(&norm)
        || crate::commands::agent_hooks::is_secret_filename(&norm)
    {
        bail!(
            "Refusing sandbox_read_paths entry '{trimmed}': cannot grant sandbox read access to vault/secret paths"
        );
    }

    for tracked in tracked_paths {
        let mut t_norm = tracked.replace('\\', "/");
        while let Some(stripped) = t_norm.strip_prefix("./") {
            t_norm = stripped.to_string();
        }
        let t_norm = t_norm.trim_end_matches('/');
        if t_norm.is_empty() {
            continue;
        }
        if norm.eq_ignore_ascii_case(t_norm)
            || norm
                .to_ascii_lowercase()
                .starts_with(&format!("{}/", t_norm.to_ascii_lowercase()))
            || t_norm
                .to_ascii_lowercase()
                .starts_with(&format!("{}/", norm.to_ascii_lowercase()))
        {
            bail!(
                "Refusing sandbox_read_paths entry '{trimmed}': overlaps vault-tracked path '{tracked}'"
            );
        }
    }

    let rel_path = Path::new(&norm);
    let canonical_root =
        std::fs::canonicalize(workspace_root).unwrap_or_else(|_| workspace_root.to_path_buf());
    let mut cursor = workspace_root.to_path_buf();
    for comp in rel_path.components() {
        cursor.push(comp);
        match std::fs::symlink_metadata(&cursor) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    bail!("Refusing symlink in sandbox_read_paths entry '{trimmed}'");
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 {
                        bail!("Refusing reparse point in sandbox_read_paths entry '{trimmed}'");
                    }
                }
                if let Ok(canon) = std::fs::canonicalize(&cursor) {
                    if !canon.starts_with(&canonical_root) {
                        bail!(
                            "sandbox_read_paths entry '{trimmed}' resolves outside workspace root"
                        );
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("inspecting sandbox_read_paths entry '{trimmed}'")
                });
            }
        }
    }

    Ok(workspace_root.join(rel_path))
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_no_net_sandbox(
    resolved_bin: &str,
    resolved_prefix: &[String],
    raw_args: &[String],
) -> Result<(String, Vec<String>)> {
    let mut last_err = String::new();
    for flag_set in [
        &["--user", "--map-root-user", "--net"][..],
        &["-r", "-n"][..],
    ] {
        let mut preflight = std::process::Command::new("unshare");
        preflight.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            preflight.env("PATH", path);
        }
        let mut test_args: Vec<&str> = flag_set.to_vec();
        test_args.extend(["--", "true"]);
        let output = preflight
            .args(&test_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .context(
                "--no-net requires `unshare` (util-linux or busybox) on Linux, which could not be executed",
            )?;
        if output.status.success() {
            let mut args: Vec<String> = flag_set.iter().map(|s| (*s).to_string()).collect();
            args.push("--".to_string());
            args.push(resolved_bin.to_string());
            args.extend(resolved_prefix.iter().cloned());
            args.extend(raw_args.iter().cloned());
            return Ok(("unshare".to_string(), args));
        }
        last_err = String::from_utf8_lossy(&output.stderr).trim().to_string();
    }
    bail!(
        "--no-net sandbox preflight failed (unprivileged user/network namespaces may be restricted): {}",
        last_err
    );
}

#[cfg(target_vendor = "apple")]
const MACOS_NO_NET_SANDBOX_PROFILE: &str = "(version 1)(allow default)\
(deny network-outbound (remote ip))\
(deny network-inbound (local ip))\
(deny network-bind (local ip))\
(deny network-outbound (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))\
(deny network-outbound (remote unix-socket (path-literal \"/var/run/mDNSResponder\")))";

#[cfg(target_vendor = "apple")]
pub(crate) fn apply_no_net_sandbox(
    resolved_bin: &str,
    resolved_prefix: &[String],
    raw_args: &[String],
) -> Result<(String, Vec<String>)> {
    let mut preflight = std::process::Command::new("/usr/bin/sandbox-exec");
    preflight.env_clear();
    let status = preflight
        .args(["-p", MACOS_NO_NET_SANDBOX_PROFILE, "/usr/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("--no-net requires /usr/bin/sandbox-exec on macOS, which could not be executed")?;
    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        bail!(
            "--no-net sandbox preflight failed on macOS: {}",
            stderr.trim()
        );
    }
    let mut args = vec![
        "-p".to_string(),
        MACOS_NO_NET_SANDBOX_PROFILE.to_string(),
        resolved_bin.to_string(),
    ];
    args.extend(resolved_prefix.iter().cloned());
    args.extend(raw_args.iter().cloned());
    Ok(("/usr/bin/sandbox-exec".to_string(), args))
}

#[cfg(target_os = "windows")]
pub(crate) mod windows_no_net {
    use anyhow::{bail, Context, Result};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::sync::OnceLock;
    use walkdir::WalkDir;
    use zeroize::Zeroizing;

    const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    const INFINITE: u32 = 0xFFFF_FFFF;
    const SE_WINDOW_OBJECT: u32 = 7;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GRANT_ACCESS: u32 = 1;
    const NO_INHERITANCE: u32 = 0;
    const NO_MULTIPLE_TRUSTEE: u32 = 0;
    const TRUSTEE_IS_SID: u32 = 0;
    const TRUSTEE_IS_WELL_KNOWN_GROUP: u32 = 5;
    const E_ALREADY_EXISTS: i32 = -2147024713; // 0x800700B7

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct SecurityCapabilities {
        app_container_sid: *mut c_void,
        capabilities: *mut c_void,
        capability_count: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        lp_reserved: *mut u16,
        lp_desktop: *mut u16,
        lp_title: *mut u16,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: isize,
        h_std_output: isize,
        h_std_error: isize,
    }

    #[repr(C)]
    struct StartupInfoExW {
        startup_info: StartupInfoW,
        lp_attribute_list: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        h_process: isize,
        h_thread: isize,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    #[repr(C)]
    struct TrusteeW {
        p_multiple_trustee: *mut c_void,
        multiple_trustee_operation: u32,
        trustee_form: u32,
        trustee_type: u32,
        ptstr_name: *mut c_void,
    }

    #[repr(C)]
    struct ExplicitAccessW {
        grf_access_permissions: u32,
        grf_access_mode: u32,
        grf_inheritance: u32,
        trustee: TrusteeW,
    }

    #[link(name = "userenv")]
    extern "system" {
        fn CreateAppContainerProfile(
            psz_app_container_name: *const u16,
            psz_display_name: *const u16,
            psz_description: *const u16,
            p_capabilities: *const c_void,
            dw_capability_count: u32,
            pp_sid_app_container_sid: *mut *mut c_void,
        ) -> i32;

        fn DeriveAppContainerSidFromAppContainerName(
            psz_app_container_name: *const u16,
            ppsid_app_container_sid: *mut *mut c_void,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn FreeSid(p_sid: *mut c_void) -> *mut c_void;
        fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
        fn GetSecurityInfo(
            handle: isize,
            object_type: u32,
            security_info: u32,
            ppsid_owner: *mut *mut c_void,
            ppsid_group: *mut *mut c_void,
            pp_dacl: *mut *mut c_void,
            pp_sacl: *mut *mut c_void,
            pp_security_descriptor: *mut *mut c_void,
        ) -> u32;
        fn SetSecurityInfo(
            handle: isize,
            object_type: u32,
            security_info: u32,
            psid_owner: *mut c_void,
            psid_group: *mut c_void,
            p_dacl: *mut c_void,
            p_sacl: *mut c_void,
        ) -> u32;
        fn SetEntriesInAclW(
            c_count_of_explicit_entries: u32,
            p_list_of_explicit_entries: *const ExplicitAccessW,
            old_acl: *mut c_void,
            new_acl: *mut *mut c_void,
        ) -> u32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetProcessWindowStation() -> isize;
        fn GetThreadDesktop(dw_thread_id: u32) -> isize;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThreadId() -> u32;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        fn CreatePipe(
            h_read_pipe: *mut isize,
            h_write_pipe: *mut isize,
            lp_pipe_attributes: *const SecurityAttributes,
            n_size: u32,
        ) -> i32;
        fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
        fn InitializeProcThreadAttributeList(
            lp_attribute_list: *mut c_void,
            dw_attribute_count: u32,
            dw_flags: u32,
            lp_size: *mut usize,
        ) -> i32;
        fn UpdateProcThreadAttribute(
            lp_attribute_list: *mut c_void,
            dw_flags: u32,
            attribute: usize,
            lp_value: *const c_void,
            cb_size: usize,
            lp_previous_value: *mut c_void,
            lp_return_size: *mut usize,
        ) -> i32;
        fn DeleteProcThreadAttributeList(lp_attribute_list: *mut c_void);
        fn CreateProcessW(
            lp_application_name: *const u16,
            lp_command_line: *mut u16,
            lp_process_attributes: *const c_void,
            lp_thread_attributes: *const c_void,
            b_inherit_handles: i32,
            dw_creation_flags: u32,
            lp_environment: *const c_void,
            lp_current_directory: *const u16,
            lp_startup_info: *const StartupInfoExW,
            lp_process_information: *mut ProcessInformation,
        ) -> i32;
        fn ReadFile(
            h_file: isize,
            lp_buffer: *mut u8,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn WaitForSingleObject(h_handle: isize, dw_milliseconds: u32) -> u32;
        fn GetExitCodeProcess(h_process: isize, lp_exit_code: *mut u32) -> i32;
        fn CloseHandle(h_object: isize) -> i32;
    }

    fn wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn quote_windows_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
            return arg.to_string();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0usize;
        for ch in arg.chars() {
            if ch == '\\' {
                backslashes += 1;
            } else if ch == '"' {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            } else {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(ch);
            }
        }
        for _ in 0..(backslashes * 2) {
            out.push('\\');
        }
        out.push('"');
        out
    }

    fn build_windows_cmdline(bin: &str, args: &[String]) -> Vec<u16> {
        let mut cmd = quote_windows_arg(bin);
        for arg in args {
            cmd.push(' ');
            cmd.push_str(&quote_windows_arg(arg));
        }
        wide_nul(&cmd)
    }

    fn build_windows_env_block(
        env_map: &BTreeMap<String, (String, Zeroizing<String>)>,
    ) -> Zeroizing<Vec<u16>> {
        let mut entries = env_map.clone();
        if !entries.contains_key("SYSTEMROOT") {
            let sr = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            entries.insert(
                "SYSTEMROOT".to_string(),
                ("SystemRoot".to_string(), Zeroizing::new(sr)),
            );
        }
        if !entries.contains_key("COMSPEC") {
            let cs = std::env::var("COMSPEC")
                .unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".to_string());
            entries.insert(
                "COMSPEC".to_string(),
                ("COMSPEC".to_string(), Zeroizing::new(cs)),
            );
        }
        if !entries.contains_key("LOCALAPPDATA") {
            if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
                entries.insert(
                    "LOCALAPPDATA".to_string(),
                    ("LOCALAPPDATA".to_string(), Zeroizing::new(local_app)),
                );
            }
        }
        let mut block: Vec<u16> = Vec::new();
        for (_upper, (k, v)) in entries {
            block.extend(k.encode_utf16());
            block.push('=' as u16);
            block.extend(v.as_str().encode_utf16());
            block.push(0);
        }
        block.push(0);
        Zeroizing::new(block)
    }

    pub(crate) struct AppContainerContext {
        sid: *mut c_void,
        caps: SecurityCapabilities,
    }

    impl Drop for AppContainerContext {
        fn drop(&mut self) {
            if !self.sid.is_null() {
                unsafe {
                    FreeSid(self.sid);
                }
                self.sid = std::ptr::null_mut();
            }
        }
    }

    impl AppContainerContext {
        pub fn new() -> Result<Self> {
            let name = wide_nul("ciphervault.no-net.v1");
            let display = wide_nul("CipherVault No-Net Sandbox");
            let desc = wide_nul("Zero-capability network-isolated execution container");
            let mut psid: *mut c_void = std::ptr::null_mut();
            let hr = unsafe {
                CreateAppContainerProfile(
                    name.as_ptr(),
                    display.as_ptr(),
                    desc.as_ptr(),
                    std::ptr::null(),
                    0,
                    &mut psid,
                )
            };
            if hr == E_ALREADY_EXISTS || (hr < 0 && psid.is_null()) {
                let hr_derive = unsafe {
                    DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut psid)
                };
                if hr_derive < 0 || psid.is_null() {
                    bail!(
                        "--no-net Windows AppContainer setup failed (CreateAppContainerProfile=0x{:08X}, Derive=0x{:08X})",
                        hr as u32,
                        hr_derive as u32
                    );
                }
            }
            Ok(Self {
                sid: psid,
                caps: SecurityCapabilities {
                    app_container_sid: psid,
                    capabilities: std::ptr::null_mut(),
                    capability_count: 0,
                    reserved: 0,
                },
            })
        }

        /// Grants `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) access to this
        /// process's in-memory WindowStation and Desktop so `user32.dll!DllMain`
        /// initializes cleanly in zero-capability AppContainers (no disk ACL changes).
        pub fn ensure_winsta_desktop_access(&self) -> Result<()> {
            static WINSTA_READY: OnceLock<std::result::Result<(), String>> = OnceLock::new();
            let res = WINSTA_READY.get_or_init(|| {
                let sid_str = wide_nul("S-1-15-2-1");
                let mut ac_sid: *mut c_void = std::ptr::null_mut();
                let ok = unsafe { ConvertStringSidToSidW(sid_str.as_ptr(), &mut ac_sid) };
                if ok == 0 || ac_sid.is_null() {
                    return Err("ConvertStringSidToSidW(S-1-15-2-1) failed".to_string());
                }
                let ea = ExplicitAccessW {
                    grf_access_permissions: GENERIC_ALL,
                    grf_access_mode: GRANT_ACCESS,
                    grf_inheritance: NO_INHERITANCE,
                    trustee: TrusteeW {
                        p_multiple_trustee: std::ptr::null_mut(),
                        multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
                        trustee_form: TRUSTEE_IS_SID,
                        trustee_type: TRUSTEE_IS_WELL_KNOWN_GROUP,
                        ptstr_name: ac_sid,
                    },
                };
                let hwinsta = unsafe { GetProcessWindowStation() };
                let hdesk = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
                let mut err_msg: Option<String> = None;
                for (label, handle) in [("WindowStation", hwinsta), ("Desktop", hdesk)] {
                    if handle == 0 {
                        continue;
                    }
                    let mut old_dacl: *mut c_void = std::ptr::null_mut();
                    let mut sd: *mut c_void = std::ptr::null_mut();
                    let rc_get = unsafe {
                        GetSecurityInfo(
                            handle,
                            SE_WINDOW_OBJECT,
                            DACL_SECURITY_INFORMATION,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            &mut old_dacl,
                            std::ptr::null_mut(),
                            &mut sd,
                        )
                    };
                    if rc_get == 0 {
                        let mut new_dacl: *mut c_void = std::ptr::null_mut();
                        let rc_acl = unsafe { SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl) };
                        if rc_acl == 0 && !new_dacl.is_null() {
                            let rc_set = unsafe {
                                SetSecurityInfo(
                                    handle,
                                    SE_WINDOW_OBJECT,
                                    DACL_SECURITY_INFORMATION,
                                    std::ptr::null_mut(),
                                    std::ptr::null_mut(),
                                    new_dacl,
                                    std::ptr::null_mut(),
                                )
                            };
                            if rc_set != 0 {
                                err_msg = Some(format!(
                                    "SetSecurityInfo({label}) failed with code {rc_set}"
                                ));
                            }
                            unsafe {
                                LocalFree(new_dacl);
                            }
                        } else {
                            err_msg = Some(format!(
                                "SetEntriesInAclW({label}) failed with code {rc_acl}"
                            ));
                        }
                        if !sd.is_null() {
                            unsafe {
                                LocalFree(sd);
                            }
                        }
                    }
                }
                unsafe {
                    LocalFree(ac_sid);
                }
                match err_msg {
                    Some(msg) => Err(msg),
                    None => Ok(()),
                }
            });
            if let Err(e) = res {
                bail!("--no-net WindowStation setup failed: {e}");
            }
            Ok(())
        }

        pub fn execute(
            &self,
            bin: &str,
            args: &[String],
            env_map: &BTreeMap<String, (String, Zeroizing<String>)>,
            stream_to_stdio: bool,
        ) -> Result<(u32, Vec<u8>, Vec<u8>)> {
            let sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: std::ptr::null_mut(),
                b_inherit_handle: 1,
            };

            let (mut in_read, mut in_write): (isize, isize) = (0, 0);
            let (mut out_read, mut out_write): (isize, isize) = (0, 0);
            let (mut err_read, mut err_write): (isize, isize) = (0, 0);
            if unsafe { CreatePipe(&mut in_read, &mut in_write, &sa, 0) } == 0
                || unsafe { CreatePipe(&mut out_read, &mut out_write, &sa, 0) } == 0
                || unsafe { CreatePipe(&mut err_read, &mut err_write, &sa, 0) } == 0
            {
                for h in [in_read, in_write, out_read, out_write, err_read, err_write] {
                    if h != 0 {
                        unsafe { CloseHandle(h) };
                    }
                }
                bail!("--no-net CreatePipe failed while preparing sandboxed stdio");
            }
            unsafe {
                SetHandleInformation(in_write as *mut c_void, HANDLE_FLAG_INHERIT, 0);
                SetHandleInformation(out_read as *mut c_void, HANDLE_FLAG_INHERIT, 0);
                SetHandleInformation(err_read as *mut c_void, HANDLE_FLAG_INHERIT, 0);
                CloseHandle(in_write);
            }

            let mut attr_size: usize = 0;
            unsafe {
                InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
            }
            let mut attr_buf = vec![0u8; attr_size.max(64)];
            let attr_ptr = attr_buf.as_mut_ptr() as *mut c_void;
            if unsafe { InitializeProcThreadAttributeList(attr_ptr, 1, 0, &mut attr_size) } == 0 {
                unsafe {
                    CloseHandle(in_read);
                    CloseHandle(out_read);
                    CloseHandle(out_write);
                    CloseHandle(err_read);
                    CloseHandle(err_write);
                }
                bail!("--no-net InitializeProcThreadAttributeList failed");
            }

            let ok_attr = unsafe {
                UpdateProcThreadAttribute(
                    attr_ptr,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    (&self.caps as *const SecurityCapabilities) as *const c_void,
                    std::mem::size_of::<SecurityCapabilities>(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok_attr == 0 {
                unsafe {
                    DeleteProcThreadAttributeList(attr_ptr);
                    CloseHandle(in_read);
                    CloseHandle(out_read);
                    CloseHandle(out_write);
                    CloseHandle(err_read);
                    CloseHandle(err_write);
                }
                bail!("--no-net UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed");
            }

            let si_ex = StartupInfoExW {
                startup_info: StartupInfoW {
                    cb: std::mem::size_of::<StartupInfoExW>() as u32,
                    lp_reserved: std::ptr::null_mut(),
                    lp_desktop: std::ptr::null_mut(),
                    lp_title: std::ptr::null_mut(),
                    dw_x: 0,
                    dw_y: 0,
                    dw_x_size: 0,
                    dw_y_size: 0,
                    dw_x_count_chars: 0,
                    dw_y_count_chars: 0,
                    dw_fill_attribute: 0,
                    dw_flags: STARTF_USESTDHANDLES,
                    w_show_window: 0,
                    cb_reserved2: 0,
                    lp_reserved2: std::ptr::null_mut(),
                    h_std_input: in_read,
                    h_std_output: out_write,
                    h_std_error: err_write,
                },
                lp_attribute_list: attr_ptr,
            };

            let mut pi = ProcessInformation {
                h_process: 0,
                h_thread: 0,
                dw_process_id: 0,
                dw_thread_id: 0,
            };

            let mut cmd_line = build_windows_cmdline(bin, args);
            let env_block = build_windows_env_block(env_map);
            let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
            let created = unsafe {
                CreateProcessW(
                    std::ptr::null(),
                    cmd_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1,
                    flags,
                    env_block.as_ptr() as *const c_void,
                    std::ptr::null(),
                    &si_ex,
                    &mut pi,
                )
            };
            drop(env_block);

            unsafe {
                DeleteProcThreadAttributeList(attr_ptr);
                CloseHandle(in_read);
                CloseHandle(out_write);
                CloseHandle(err_write);
            }

            if created == 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    CloseHandle(out_read);
                    CloseHandle(err_read);
                }
                return Err(err).with_context(|| {
                    format!("--no-net CreateProcessW failed for command '{bin}'")
                });
            }

            fn read_pipe(handle: isize, is_stderr: bool, stream_to_stdio: bool) -> Vec<u8> {
                let mut acc = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let mut read_bytes: u32 = 0;
                    let ok = unsafe {
                        ReadFile(
                            handle,
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                            &mut read_bytes,
                            std::ptr::null_mut(),
                        )
                    };
                    if ok == 0 || read_bytes == 0 {
                        break;
                    }
                    let slice = &buf[..read_bytes as usize];
                    if stream_to_stdio {
                        if is_stderr {
                            let _ = std::io::stderr().write_all(slice);
                            let _ = std::io::stderr().flush();
                        } else {
                            let _ = std::io::stdout().write_all(slice);
                            let _ = std::io::stdout().flush();
                        }
                    } else {
                        acc.extend_from_slice(slice);
                    }
                }
                unsafe {
                    CloseHandle(handle);
                }
                acc
            }

            let t_out = std::thread::spawn(move || read_pipe(out_read, false, stream_to_stdio));
            let t_err = std::thread::spawn(move || read_pipe(err_read, true, stream_to_stdio));

            unsafe {
                WaitForSingleObject(pi.h_process, INFINITE);
            }
            let mut exit_code: u32 = 1;
            unsafe {
                GetExitCodeProcess(pi.h_process, &mut exit_code);
                CloseHandle(pi.h_process);
                CloseHandle(pi.h_thread);
            }

            let stdout_buf = t_out.join().unwrap_or_default();
            let stderr_buf = t_err.join().unwrap_or_default();
            Ok((exit_code, stdout_buf, stderr_buf))
        }

        pub fn preflight(&self) -> Result<()> {
            let mut env_map = BTreeMap::new();
            let sr = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            env_map.insert(
                "SYSTEMROOT".to_string(),
                ("SystemRoot".to_string(), Zeroizing::new(sr)),
            );
            let args = vec!["/c".to_string(), "exit".to_string(), "0".to_string()];
            let (code, _, _) = self
                .execute("C:\\Windows\\System32\\cmd.exe", &args, &env_map, false)
                .context("--no-net AppContainer preflight could not launch cmd.exe")?;
            if code != 0 {
                bail!("--no-net AppContainer preflight exited with code 0x{code:08X}");
            }
            Ok(())
        }
    }

    fn is_windows_system_path(path: &Path) -> bool {
        let lower = path.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
        lower.contains("\\windows\\system32\\")
            || lower.contains("\\windows\\syswow64\\")
            || lower.eq_ignore_ascii_case("cmd.exe")
    }

    fn grant_appcontainer_rx(path: &Path, is_dir: bool) {
        if is_windows_system_path(path) {
            return;
        }
        let mut cmd = std::process::Command::new("C:\\Windows\\System32\\icacls.exe");
        cmd.arg(path).arg("/grant");
        if is_dir {
            if let Ok(user) = std::env::var("USERNAME") {
                if !user.trim().is_empty() {
                    cmd.arg(format!("{user}:(OI)(CI)(F)"));
                }
            }
            cmd.arg("*S-1-15-2-1:(OI)(CI)(RX)");
        } else {
            if let Ok(user) = std::env::var("USERNAME") {
                if !user.trim().is_empty() {
                    cmd.arg(format!("{user}:(F)"));
                }
            }
            cmd.arg("*S-1-15-2-1:(RX)");
        }
        let _ = cmd
            .arg("/Q")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }

    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    /// Packs Python's standard library (`Lib/` excluding `site-packages`, `test`,
    /// UI toolkits, and `__pycache__`) into an uncompressed STORED zip archive so
    /// CPython's built-in zipimport resolves stdlib inside the staged cache dir.
    fn write_python_stdlib_zip(lib_dir: &Path, zip_dest: &Path) -> Result<()> {
        let skip_dirs = [
            "site-packages",
            "test",
            "idlelib",
            "tkinter",
            "turtledemo",
            "pydoc_data",
            "ensurepip",
            "__pycache__",
        ];
        struct CentralEntry {
            name: Vec<u8>,
            crc: u32,
            size: u32,
            offset: u32,
        }
        let mut file = std::fs::File::create(zip_dest)
            .with_context(|| format!("create {}", zip_dest.display()))?;
        let mut central = Vec::new();
        let mut offset: u32 = 0;
        let walker = WalkDir::new(lib_dir).into_iter().filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                return !skip_dirs.iter().any(|skip| name.eq_ignore_ascii_case(skip));
            }
            true
        });
        for entry in walker.filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("py") {
                continue;
            }
            let Ok(rel) = path.strip_prefix(lib_dir) else {
                continue;
            };
            let rel_name = rel.to_string_lossy().replace('\\', "/");
            let name_bytes = rel_name.as_bytes();
            let data = std::fs::read(path)?;
            if data.len() > u32::MAX as usize || name_bytes.len() > u16::MAX as usize {
                continue;
            }
            let size = data.len() as u32;
            let crc = crc32_ieee(&data);

            // Local file header (30 bytes + name)
            let mut lfh = Vec::with_capacity(30 + name_bytes.len());
            lfh.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
            lfh.extend_from_slice(&20u16.to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(&crc.to_le_bytes());
            lfh.extend_from_slice(&size.to_le_bytes());
            lfh.extend_from_slice(&size.to_le_bytes());
            lfh.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            lfh.extend_from_slice(&0u16.to_le_bytes());
            lfh.extend_from_slice(name_bytes);
            file.write_all(&lfh)?;
            file.write_all(&data)?;

            central.push(CentralEntry {
                name: name_bytes.to_vec(),
                crc,
                size,
                offset,
            });
            offset = offset
                .checked_add(lfh.len() as u32 + size)
                .context("stdlib zip exceeded 4 GiB limit")?;
        }

        let cd_offset = offset;
        let mut cd_size: u32 = 0;
        for c in &central {
            let mut cdfh = Vec::with_capacity(46 + c.name.len());
            cdfh.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
            cdfh.extend_from_slice(&20u16.to_le_bytes());
            cdfh.extend_from_slice(&20u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&c.crc.to_le_bytes());
            cdfh.extend_from_slice(&c.size.to_le_bytes());
            cdfh.extend_from_slice(&c.size.to_le_bytes());
            cdfh.extend_from_slice(&(c.name.len() as u16).to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u16.to_le_bytes());
            cdfh.extend_from_slice(&0u32.to_le_bytes());
            cdfh.extend_from_slice(&c.offset.to_le_bytes());
            cdfh.extend_from_slice(&c.name);
            file.write_all(&cdfh)?;
            cd_size += cdfh.len() as u32;
        }
        let count = central.len() as u16;
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&cd_size.to_le_bytes());
        eocd.extend_from_slice(&cd_offset.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        file.write_all(&eocd)?;
        file.sync_all()?;
        Ok(())
    }

    fn stage_runtime_executable(exe_path: &Path) -> Result<String> {
        if is_windows_system_path(exe_path) || !exe_path.is_file() {
            return Ok(exe_path.to_string_lossy().to_string());
        }
        let canonical = std::fs::canonicalize(exe_path).unwrap_or_else(|_| exe_path.to_path_buf());
        let meta = std::fs::metadata(&canonical)?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut hasher = Sha256::new();
        hasher.update(b"cv-ac-v2:");
        hasher.update(canonical.to_string_lossy().as_bytes());
        hasher.update(meta.len().to_le_bytes());
        hasher.update(mtime.to_le_bytes());
        let cache_id = &hex::encode(hasher.finalize())[..16];

        let cache_root = std::env::temp_dir().join("ciphervault-ac-cache");
        let _ = std::fs::create_dir_all(&cache_root);
        grant_appcontainer_rx(&cache_root, true);
        let cache_dir = cache_root.join(cache_id);
        let file_name = canonical
            .file_name()
            .context("executable has no filename")?;
        let staged_exe = cache_dir.join(file_name);

        if staged_exe.is_file() {
            return Ok(staged_exe.to_string_lossy().to_string());
        }

        let tmp_dir = cache_root.join(format!("{cache_id}.tmp.{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir)?;
        grant_appcontainer_rx(&tmp_dir, true);

        let parent = canonical.parent().context("executable has no parent dir")?;
        std::fs::copy(&canonical, tmp_dir.join(file_name))?;
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                        if ext.eq_ignore_ascii_case("dll") {
                            if let Some(fname) = p.file_name() {
                                let _ = std::fs::copy(&p, tmp_dir.join(fname));
                            }
                        }
                    }
                }
            }
        }

        // Python runtime support: stage DLLs/*.pyd + *.dll and pack Lib/ into python3XX.zip.
        let lib_dir = parent.join("Lib");
        let dlls_dir = parent.join("DLLs");
        if lib_dir.is_dir() && dlls_dir.is_dir() {
            let staged_dlls = tmp_dir.join("DLLs");
            let _ = std::fs::create_dir_all(&staged_dlls);
            if let Ok(entries) = std::fs::read_dir(&dlls_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let p = entry.path();
                    if p.is_file() {
                        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                            if ext.eq_ignore_ascii_case("pyd") || ext.eq_ignore_ascii_case("dll") {
                                if let Some(fname) = p.file_name() {
                                    let _ = std::fs::copy(&p, staged_dlls.join(fname));
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let fname = entry.file_name().to_string_lossy().to_ascii_lowercase();
                    if fname.starts_with("python3") && fname.ends_with(".dll") {
                        let stem = fname.trim_end_matches(".dll");
                        let zip_name = format!("{stem}.zip");
                        if !tmp_dir.join(&zip_name).exists() {
                            let _ = write_python_stdlib_zip(&lib_dir, &tmp_dir.join(&zip_name));
                        }
                    }
                }
            }
        }

        grant_appcontainer_rx(&tmp_dir, true);
        if std::fs::rename(&tmp_dir, &cache_dir).is_err() && !staged_exe.is_file() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            bail!(
                "Failed to populate AppContainer runtime cache for {}",
                exe_path.display()
            );
        }
        grant_appcontainer_rx(&cache_dir, true);
        Ok(staged_exe.to_string_lossy().to_string())
    }

    fn grant_appcontainer_rx_readonly(path: &Path, is_dir: bool) {
        if is_windows_system_path(path) {
            return;
        }
        let mut cmd = std::process::Command::new("C:\\Windows\\System32\\icacls.exe");
        cmd.arg(path).arg("/grant");
        if is_dir {
            cmd.arg("*S-1-15-2-1:(OI)(CI)(RX)");
        } else {
            cmd.arg("*S-1-15-2-1:(RX)");
        }
        let _ = cmd
            .arg("/Q")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }

    pub(crate) fn grant_sandbox_read_paths(
        workspace_root: &Path,
        rel_paths: &[String],
        tracked_paths: &[String],
    ) -> Result<()> {
        for rel in rel_paths {
            let full = super::validate_sandbox_read_path(rel, workspace_root, tracked_paths)?;
            match std::fs::symlink_metadata(&full) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        bail!("Refusing symlink in sandbox_read_paths entry '{rel}'");
                    }
                    grant_appcontainer_rx_readonly(&full, meta.is_dir());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("inspecting sandbox_read_paths entry '{rel}'")
                    });
                }
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_command(
        resolved_bin: &str,
        resolved_prefix: &[String],
        raw_args: &[String],
    ) -> Result<(String, Vec<String>)> {
        let staged_bin = stage_runtime_executable(Path::new(resolved_bin))?;
        let mut combined = resolved_prefix.to_vec();
        // Grant AppContainer read access to existing script/batch files in prefix/args
        // and temp working directories so temp-dir scripts and .cmd shims run cleanly.
        if let Ok(cwd) = std::env::current_dir() {
            let temp_root = std::env::temp_dir();
            if cwd.starts_with(&temp_root) {
                grant_appcontainer_rx(&cwd, true);
            }
        }
        for arg in resolved_prefix.iter().chain(raw_args.iter()) {
            if !arg.starts_with('-') && arg.len() <= 512 {
                let p = Path::new(arg);
                if p.is_file() && !is_windows_system_path(p) {
                    grant_appcontainer_rx(p, false);
                }
            }
        }
        let stem = Path::new(&staged_bin)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if (stem == "node" || stem == "node.exe")
            && !raw_args.iter().any(|a| a == "--preserve-symlinks-main")
        {
            combined.push("--preserve-symlinks-main".to_string());
        }
        combined.extend(raw_args.iter().cloned());
        Ok((staged_bin, combined))
    }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "windows")))]
pub(crate) fn apply_no_net_sandbox(
    _resolved_bin: &str,
    _resolved_prefix: &[String],
    _raw_args: &[String],
) -> Result<(String, Vec<String>)> {
    bail!(
        "--no-net network sandboxing is not supported without unprivileged network namespaces on this OS \
         (supported on Linux via `unshare`, macOS via `sandbox-exec`, and Windows via AppContainer). Refusing to run with unrestricted network access."
    )
}
