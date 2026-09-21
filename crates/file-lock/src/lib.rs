//! Lock secret files down to the current user.
//!
//! Equivalent of Unix `chmod 0600`, plus a Windows implementation that sets
//! a protected (inheritance-disabled) DACL granting only the current user.
//! Both binaries used to shell out to `icacls` for this; that proved flaky
//! on some machines (exit 0 while leaving inherited ACEs in place), so
//! Windows now uses direct `advapi32` syscalls via hand-rolled FFI, in the
//! same zero-dependency style as the rest of the codebase.

use std::io;
use std::path::Path;

/// Restrict `path` so only the current user can read or write it.
///
/// The best-effort contract lives with the CALLER: this returns `Err`
/// (carrying the OS error) when the lockdown cannot be applied, and callers
/// that must not brick setup on exotic filesystems warn and continue.
pub fn lock_secret_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return imp::lock_secret_file(path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file locking is not supported on this platform",
        ))
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    type Handle = *mut c_void;
    type Dword = u32;
    type Bool = i32;
    type Psid = *mut c_void;
    type Pacl = *mut Acl;

    const TOKEN_QUERY: Dword = 0x0008;
    const TOKEN_USER_CLASS: Dword = 1;
    const ACL_REVISION: Dword = 2;
    const SE_FILE_OBJECT: Dword = 1;
    const DACL_SECURITY_INFORMATION: Dword = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: Dword = 0x8000_0000;
    const ERROR_SUCCESS: Dword = 0;

    // FILE_GENERIC_READ | FILE_GENERIC_WRITE, spelled from parts so the
    // mask stays auditable (equivalent of the old icacls `(R,W)` grant).
    const STANDARD_RIGHTS_READ: Dword = 0x0002_0000;
    const STANDARD_RIGHTS_WRITE: Dword = 0x0002_0000;
    const SYNCHRONIZE: Dword = 0x0010_0000;
    const FILE_READ_DATA: Dword = 0x0001;
    const FILE_READ_ATTRIBUTES: Dword = 0x0080;
    const FILE_READ_EA: Dword = 0x0008;
    const FILE_WRITE_DATA: Dword = 0x0002;
    const FILE_WRITE_ATTRIBUTES: Dword = 0x0100;
    const FILE_WRITE_EA: Dword = 0x0010;
    const FILE_APPEND_DATA: Dword = 0x0004;
    const FILE_GENERIC_READ: Dword =
        STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
    const FILE_GENERIC_WRITE: Dword = STANDARD_RIGHTS_WRITE
        | FILE_WRITE_DATA
        | FILE_WRITE_ATTRIBUTES
        | FILE_WRITE_EA
        | FILE_APPEND_DATA
        | SYNCHRONIZE;

    #[repr(C)]
    struct SidAndAttributes {
        sid: Psid,
        attributes: Dword,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct Acl {
        acl_revision: u8,
        sbz1: u8,
        acl_size: u16,
        ace_count: u16,
        sbz2: u16,
    }

    #[repr(C)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    #[repr(C)]
    struct AccessAllowedAce {
        header: AceHeader,
        mask: Dword,
        sid_start: Dword,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn OpenProcessToken(process: Handle, desired_access: Dword, token: *mut Handle) -> Bool;
        fn CloseHandle(object: Handle) -> Bool;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn GetTokenInformation(
            token: Handle,
            class: Dword,
            info: *mut c_void,
            len: Dword,
            needed: *mut Dword,
        ) -> Bool;
        fn GetLengthSid(sid: Psid) -> Dword;
        fn InitializeAcl(acl: Pacl, len: Dword, revision: Dword) -> Bool;
        fn AddAccessAllowedAce(acl: Pacl, revision: Dword, mask: Dword, sid: Psid) -> Bool;
        fn SetNamedSecurityInfoW(
            name: *const u16,
            obj_type: Dword,
            info: Dword,
            owner: Psid,
            group: Psid,
            dacl: Pacl,
            sacl: Pacl,
        ) -> Dword;
    }

    pub(super) fn lock_secret_file(path: &Path) -> io::Result<()> {
        // Win32 accepts forward slashes; still normalize so any
        // diagnostics show the canonical form.
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        for w in wide.iter_mut() {
            if *w == u16::from(b'/') {
                *w = u16::from(b'\\');
            }
        }
        wide.push(0);

        // Current user SID from the process token. GetCurrentProcess
        // returns a pseudo-handle: never CloseHandle it.
        unsafe {
            let mut token: Handle = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let result = lock_with_token(&wide, token);
            let _ = CloseHandle(token);
            result
        }
    }

    /// Fetch the token's user SID, build a single-ACE DACL for it, and
    /// apply it as a PROTECTED DACL (inheritance disabled, every inherited
    /// ACE dropped). Never applies a half-built DACL: an empty DACL denies
    /// all access, so every build step must succeed before the apply call.
    unsafe fn lock_with_token(wide: &[u16], token: Handle) -> io::Result<()> {
        let mut needed: Dword = 0;
        // Size query: FALSE + ERROR_INSUFFICIENT_BUFFER is the expected path.
        let _ = GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64 backing keeps the TOKEN_USER struct aligned.
        let mut token_buf = vec![0u64; (needed as usize).div_ceil(8)];
        if GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            token_buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sid = (*(token_buf.as_ptr() as *const TokenUser)).user.sid;
        if sid.is_null() {
            return Err(io::Error::other("process token has no user SID"));
        }

        let sid_len = GetLengthSid(sid) as usize;
        let acl_len =
            std::mem::size_of::<Acl>() + std::mem::size_of::<AccessAllowedAce>() - 4 + sid_len;
        let mut acl_buf = vec![0u64; acl_len.div_ceil(8)];
        let acl = acl_buf.as_mut_ptr() as Pacl;
        if InitializeAcl(acl, acl_len as Dword, ACL_REVISION) == 0 {
            return Err(io::Error::last_os_error());
        }
        if AddAccessAllowedAce(
            acl,
            ACL_REVISION,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            sid,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let status = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        );
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "cv-filelock-{tag}-{}-{nanos}.txt",
            std::process::id()
        ))
    }

    /// The strict end-state property both binaries used to assert
    /// separately: after locking, the file stays readable by us, grants
    /// the current user, and carries no inherited group ACEs.
    #[cfg(windows)]
    #[test]
    fn lockdown_grants_only_current_user() {
        let path = unique_temp_path("win");
        std::fs::write(&path, "secret").unwrap();
        // Forward-slash form must work: callers pass Rust display paths.
        let slashed = path.to_string_lossy().replace('\\', "/");
        lock_secret_file(std::path::Path::new(&slashed)).expect("lockdown must succeed");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
        // Read-only use of icacls as an independent oracle for the ACL.
        let query = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        assert!(query.status.success());
        let listing = String::from_utf8_lossy(&query.stdout).to_ascii_lowercase();
        let user = std::env::var("USERNAME").unwrap().to_ascii_lowercase();
        assert!(
            listing.contains(&user),
            "lockdown should grant {user}: {listing}"
        );
        assert!(
            !listing.contains("builtin"),
            "lockdown should strip inherited groups: {listing}"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lockdown_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = unique_temp_path("unix");
        std::fs::write(&path, "secret").unwrap();
        lock_secret_file(&path).expect("lockdown must succeed");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
        std::fs::remove_file(&path).unwrap();
    }
}
