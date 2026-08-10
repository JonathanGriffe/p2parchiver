//! `ac-server client` — inspect and revoke enrolled clients.

use anyhow::{Context, Result};

use ac_net::PeerId;
use ac_net::config::Paths;

use crate::store::now;

pub fn list(paths: &Paths) -> Result<()> {
    let clients = super::open_store(paths)?
        .list_clients()
        .context("listing clients")?;

    if clients.is_empty() {
        println!("no clients enrolled yet");
        return Ok(());
    }

    // A client with no username predates them, and its old label collided with another's
    // during the upgrade. It can still use the server, but cannot be issued an attestation
    // — so it is worth naming as a thing to fix rather than printing as a blank.
    let name = |c: &crate::store::ClientRecord| {
        c.username.clone().unwrap_or_else(|| "(no username)".into())
    };

    let widest = clients.iter().map(|c| name(c).len()).max().unwrap_or(0);
    for client in &clients {
        let status = match (client.is_revoked(), client.username.is_none()) {
            (true, _) => "  (revoked)",
            (false, true) => "  (must re-enrol to get an attestation)",
            (false, false) => "",
        };
        println!("{:<widest$}  {}{status}", name(client), client.peer);
    }
    Ok(())
}

pub fn revoke(paths: &Paths, peer: &PeerId) -> Result<()> {
    let revoked = super::open_store(paths)?
        .revoke(peer, now())
        .with_context(|| format!("revoking {peer}"))?;

    if revoked {
        println!("revoked {peer}");
        // A running server sweeps for this on its housekeeping tick and closes whatever the
        // peer still holds, circuits included. Said in seconds rather than "immediately"
        // because this process only writes the store — the daemon is what acts on it, and if
        // none is running the change takes effect when one next starts.
        println!("a running server drops their connection within a few seconds");
        // Worth saying, because a revoked peer cannot reach enrolment either: issuing
        // them a fresh invite will not work, and the failure looks like a network fault.
        println!("to reverse this later: ac-server client unrevoke {peer}");
    } else {
        println!("no active client with peer id {peer}");
    }
    Ok(())
}

pub fn unrevoke(paths: &Paths, peer: &PeerId) -> Result<()> {
    let restored = super::open_store(paths)?
        .unrevoke(peer)
        .with_context(|| format!("restoring {peer}"))?;

    if restored {
        println!("restored {peer}; they may connect again");
    } else {
        println!("no revoked client with peer id {peer}");
    }
    Ok(())
}
