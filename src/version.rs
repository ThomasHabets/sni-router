/// Build metadata shared by both binaries' startup messages.
pub(crate) fn version_string() -> String {
    let version = if env!("GIT_VERSION").is_empty() {
        env!("CARGO_PKG_VERSION")
    } else {
        &format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("GIT_VERSION"))
    };
    format!(
        "{version} built with {} in mode {}",
        env!("RUSTC_VERSION"),
        env!("BUILD_PROFILE"),
    )
}
