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

    let widest = clients.iter().map(|c| c.label.len()).max().unwrap_or(0);
    for client in clients {
        let status = if client.is_revoked() {
            "  (revoked)"
        } else {
            ""
        };
        println!("{:<widest$}  {}{status}", client.label, client.peer);
    }
    Ok(())
}

pub fn revoke(paths: &Paths, peer: &PeerId) -> Result<()> {
    let revoked = super::open_store(paths)?
        .revoke(peer, now())
        .with_context(|| format!("revoking {peer}"))?;

    if revoked {
        println!("revoked {peer}");
        // Denial runs when a connection is established, so one already open survives
        // until it ends on its own. What matters is that the peer cannot reconnect, and
        // from stage 6 cannot renew a relay reservation or rendezvous registration.
        println!("takes effect on their next connection; an open one may persist briefly");
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
