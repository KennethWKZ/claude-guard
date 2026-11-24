//! The user database (Python's `pwd` module): the home folder of this account or of a named one. guard-read-keys
//! looks up the real home folder here, not in `$HOME`, which a repo's settings `env` can override.
//! Three libc calls declared by hand: the `libc` crate would bring a build script for them.

use std::ffi::{CStr, CString, c_char};

#[cfg(not(target_os = "macos"))]
compile_error!("struct passwd below is macOS's layout");

#[repr(C)]
struct Passwd {
    pw_name: *mut c_char,
    pw_passwd: *mut c_char,
    pw_uid: u32,
    pw_gid: u32,
    pw_change: i64,
    pw_class: *mut c_char,
    pw_gecos: *mut c_char,
    pw_dir: *mut c_char,
    pw_shell: *mut c_char,
    pw_expire: i64,
}

unsafe extern "C" {
    fn getuid() -> u32;
    fn getpwuid(uid: u32) -> *mut Passwd;
    fn getpwnam(name: *const c_char) -> *mut Passwd;
}

fn dir_of(p: *mut Passwd) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a non-null entry from getpwuid/getpwnam; pw_dir is a C string owned by libc, copied at once.
    unsafe {
        let d = (*p).pw_dir;
        if d.is_null() {
            return None;
        }
        Some(CStr::from_ptr(d).to_string_lossy().into_owned())
    }
}

/// `pwd.getpwuid(os.getuid()).pw_dir`; None where Python raised KeyError.
pub fn own_home() -> Option<String> {
    // SAFETY: plain libc calls; this binary is single-threaded where it calls them.
    unsafe { dir_of(getpwuid(getuid())) }
}

/// `pwd.getpwnam(name).pw_dir`. Ok(None) where Python raised KeyError, Err where it raised ValueError
/// (a null byte in the name).
pub fn home_of(name: &str) -> Result<Option<String>, String> {
    let c = CString::new(name).map_err(|_| "ValueError: embedded null character".to_string())?;
    // SAFETY: as above; `c` outlives the call.
    Ok(unsafe { dir_of(getpwnam(c.as_ptr())) })
}
