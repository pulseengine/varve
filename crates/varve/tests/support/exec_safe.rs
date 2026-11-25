//! Put an executable in place for a test that will exec it (#400).
//!
//! Tests in one binary run on parallel threads, and many of them spawn
//! processes. A child forked by another thread while this process holds a
//! writable descriptor on a file inherits that descriptor until its own exec
//! closes it. An exec of the file in that window fails with ETXTBSY ("Text
//! file busy"). Every executable a test writes and later runs goes through
//! these functions.
#![allow(dead_code)]

use std::path::Path;

/// Copy `src` to `dst` and make `dst` executable (0o755).
pub fn install_executable(src: &Path, dst: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::copy(src, dst).unwrap();
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Write `body` to `dst` and make `dst` executable (0o755).
pub fn write_executable(dst: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::write(dst, body).unwrap();
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755)).unwrap();
}
