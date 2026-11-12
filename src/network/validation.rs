use crate::error::NetavarkResult;
use log::debug;

/// Check that the netns argument names something we can use: a netns file
/// on Linux, a jail on FreeBSD.
#[cfg(target_os = "linux")]
pub fn ns_checks(file: &str) -> NetavarkResult<()> {
    debug!("Validating network namespace...");
    // TODO check for FS_MAGIC
    let _ = std::fs::File::open(file)?.metadata()?;
    Ok(())
}

#[cfg(target_os = "freebsd")]
pub fn ns_checks(name: &str) -> NetavarkResult<()> {
    debug!("Validating network namespace...");
    let _ = crate::network::netns::Netns::open(name)?;
    Ok(())
}
