use anyhow::{Context, Result, anyhow};
use caps::CapSet;
use tracing::{info, trace, warn};

/// Drop privs suitable for SNI router.
///
/// # Errors
///
/// If dropping privs fails.
///
// Not actually dead code, just not used in tarweb, only SNI.
#[allow(dead_code)]
pub(crate) fn sni_drop(dirs: &[&std::path::Path], write_keylogfile: bool) -> Result<()> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        Scope, path_beneath_rules,
    };

    drop_caps()?;

    let abi = ABI::V6;

    // Kernel 5.13 or better. tarweb already requires 6.7.
    let status = {
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))?
            .handle_access(AccessNet::BindTcp)?
            .create()?
            .set_no_new_privs(true)
            .add_rules(path_beneath_rules(dirs, AccessFs::from_read(abi)))?;
        if let Ok(k) = std::env::var("SSLKEYLOGFILE")
            && write_keylogfile
        {
            let keylogfile = std::path::PathBuf::from(k);
            // Create it if it doesn't exist.
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&keylogfile);
            ruleset =
                ruleset.add_rules(path_beneath_rules(&[keylogfile], AccessFs::from_write(abi)))?;
        }
        ruleset
    }
    .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock enabled and fully enforced for filesystem and network");
        }
        other => {
            return Err(anyhow!(
                "Landlock status not fully enforced for filesystem and network: {other:?}"
            ));
        }
    }

    // These require kernel 6.12 or newer.
    let status = Ruleset::default()
        .scope(Scope::Signal)?
        // .scope(Scope::AbstractUnixSocket)?
        .create()?
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock enabled and fully enforced for signal");
        }
        other => warn!(
            "Landlock status not fully enforced for signal (probably kernel <6.12): {other:?}"
        ),
    }

    // Confirm access denied.
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(_) => return Err(anyhow!("landlock failed to prevent tcp bind")),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(e) => {
            return Err(anyhow!(
                "unexpected error verifying landlock blocking connects: {e}"
            ));
        }
    }
    Ok(())
}

/// Drop privs suitable for the UDP HTTP/3 router.
///
/// Landlock currently only supports TCP network rights, so this confines file
/// system access and signal delivery, and drops Linux capabilities. The UDP
/// socket must be bound before calling this.
///
/// # Errors
///
/// If dropping privs fails.
#[allow(dead_code)]
pub(crate) fn h3_drop(dirs: &[&std::path::Path]) -> Result<()> {
    use landlock::{
        ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
        path_beneath_rules,
    };

    drop_caps()?;

    let abi = ABI::V6;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .set_no_new_privs(true)
        .add_rules(path_beneath_rules(dirs, AccessFs::from_read(abi)))?
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock enabled and fully enforced for filesystem");
        }
        other => {
            return Err(anyhow!(
                "Landlock status not fully enforced for filesystem: {other:?}"
            ));
        }
    }

    let status = Ruleset::default()
        .scope(Scope::Signal)?
        .create()?
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock enabled and fully enforced for signal");
        }
        other => warn!(
            "Landlock status not fully enforced for signal (probably kernel <6.12): {other:?}"
        ),
    }

    Ok(())
}

/// Drop all capabilities, if present.
fn drop_caps() -> Result<()> {
    trace!("Dropping caps");

    // These should not fail.
    for set in [
        CapSet::Effective,
        CapSet::Inheritable,
        CapSet::Ambient,
        CapSet::Permitted,
    ] {
        caps::clear(None, set).context(format!("dropping privs for {set:?}"))?;
    }

    // Dropping bounding caps can fail.
    {
        let set = CapSet::Bounding;
        if let Err(e) = caps::clear(None, set) {
            trace!("Expected: Dropping priv {set:?} failed: {e}");
        }
    }
    Ok(())
}
