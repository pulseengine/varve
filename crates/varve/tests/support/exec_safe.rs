//! Put an executable in place for a test that will exec it (#400).
//!
//! Tests in one binary run on parallel threads, and many of them spawn
//! processes. A child forked by another thread while this process holds a
//! writable descriptor on a file inherits that descriptor until its own exec
//! closes it. An exec of the file in that window fails with ETXTBSY ("Text
//! file busy"). Every executable a test writes and later runs goes through
//! these functions, which leave the only writable descriptor to a `/bin/cp`
//! child that has exited before they return.
#![allow(dead_code)]

use std::path::Path;

/// Copy `src` to `dst` and make `dst` executable (0o755).
pub fn install_executable(src: &Path, dst: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    let st = std::process::Command::new("/bin/cp")
        .arg(src)
        .arg(dst)
        .status()
        .expect("run /bin/cp");
    assert!(
        st.success(),
        "/bin/cp {} {}: {st}",
        src.display(),
        dst.display()
    );
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Write `body` to `dst` and make `dst` executable (0o755). The body is
/// written here to a staging file that is never exec'd, then copied.
pub fn write_executable(dst: &Path, body: &str) {
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    let staged = dst.with_file_name(format!(
        ".{}.staged",
        dst.file_name().unwrap().to_string_lossy()
    ));
    std::fs::write(&staged, body).unwrap();
    install_executable(&staged, dst);
    std::fs::remove_file(&staged).unwrap();
}
