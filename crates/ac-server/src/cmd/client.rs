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
        println!("a running server drops their connection within a few seconds");
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
