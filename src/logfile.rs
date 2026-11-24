//! Append-only logs (crash logs, the husky error log, the shadow log): one `write` per record, so records from
//! parallel hooks never run together, and a size cap, so a crash loop can't grow a log (which may hold the start of
//! a command) without limit. At the cap the log moves to `<path>.1` (replacing the previous one) and starts again.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

pub const CRASH_CAP: u64 = 1_000_000;
pub const SHADOW_CAP: u64 = 50_000_000;

/// Append `record` (a trailing newline is added if missing). Never fails the caller.
pub fn append(path: &str, record: &str, cap: u64) {
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir);
    }
    if fs::metadata(path).is_ok_and(|m| m.len() >= cap) {
        let _ = fs::rename(path, format!("{path}.1"));
    }
    let mut buf = record.to_string();
    if !buf.ends_with('\n') {
        buf.push('\n');
    }
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    {
        let _ = f.write_all(buf.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn one_record_per_write_and_rotation() {
        let d = std::env::temp_dir().join(format!("claude-guard-logfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("x.log").to_string_lossy().into_owned();
        for i in 0..5 {
            super::append(&p, &format!("record {i}"), 30);
        }
        let cur = std::fs::read_to_string(&p).unwrap();
        let old = std::fs::read_to_string(format!("{p}.1")).unwrap();
        assert!(
            cur.lines().count() <= 3 && old.lines().count() >= 1,
            "{cur:?} {old:?}"
        );
        assert!(cur.ends_with("record 4\n"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
