fn main() {
    // Build proto.
    let mut prost_build = prost_build::Config::new();
    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    prost_build
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .file_descriptor_set_path(out_dir.join("descriptor.bin"))
        .compile_protos(&["proto/sni_router.proto"], &["proto"])
        .unwrap();

    // Add git version.
    let git = std::process::Command::new("git")
        .args(["describe", "--tags", "--dirty", "--always"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=GIT_VERSION={}", git.trim());

    // Add compiler version.
    {
        let rustc = std::env::var("RUSTC").unwrap();
        let out = std::process::Command::new(rustc)
            .arg("--version")
            .output()
            .unwrap();
        let version = String::from_utf8(out.stdout).unwrap();
        println!("cargo:rustc-env=RUSTC_VERSION={version}");
    }

    let profile = std::env::var("PROFILE").unwrap();
    println!("cargo:rustc-env=BUILD_PROFILE={profile}");
}
