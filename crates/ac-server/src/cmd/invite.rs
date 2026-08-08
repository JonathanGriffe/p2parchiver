//! `ac-server invite` — mint and inspect invite codes.

use anyhow::{Context, Result};

use ac_net::config::Paths;
use ac_net::identity::Identity;

use crate::invite::InviteCode;
use crate::store::now;

pub fn new(paths: &Paths, label: &str, ttl_hours: i64) -> Result<()> {
    let store = super::open_store(paths)?;

    let code = InviteCode::generate().context("reading system randomness")?;
    let expires_at = now() + ttl_hours * 3600;
    store
        .create_invite(&code, label, expires_at)
        .with_context(|| format!("recording an invite for {label}"))?;

    let identity = Identity::load(&paths.identity_file())
        .context("loading the server identity; run `ac-server init` first")?;

    // The code is shown exactly once. Only its hash is stored, so it cannot be recovered
    // from the database if it is lost — that is the point, not a limitation.
    println!("invite  {code}");
    println!("label   {label}");
    println!("expires in {ttl_hours}h");
    println!("server  {}", identity.peer_id());
    println!();
    println!("This code is shown once and is not recoverable. It is a bearer secret:");
    println!("whoever holds it can enrol. Send it over a channel you trust.");

    Ok(())
}

pub fn list(paths: &Paths) -> Result<()> {
    let invites = super::open_store(paths)?
        .list_invites()
        .context("listing invites")?;

    if invites.is_empty() {
        println!("no invites. create one with: ac-server invite new --label <name>");
        return Ok(());
    }

    let now = now();
    let widest = invites.iter().map(|i| i.label.len()).max().unwrap_or(0);

    for invite in invites {
        let status = match (&invite.redeemed_by, invite.expires_at > now) {
            (Some(peer), _) => format!("redeemed by {peer}"),
            (None, true) => format!(
                "pending, expires in {}",
                human_duration(invite.expires_at - now)
            ),
            (None, false) => "expired".to_owned(),
        };
        // The hash prefix identifies a row without being usable as a code.
        println!(
            "{:<widest$}  {}…  {status}",
            invite.label,
            &invite.code_hash[..8]
        );
    }
    Ok(())
}

fn human_duration(seconds: i64) -> String {
    match seconds {
        s if s >= 86_400 => format!("{}d", s / 86_400),
        s if s >= 3_600 => format!("{}h", s / 3_600),
        s if s >= 60 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_in_the_largest_useful_unit() {
        assert_eq!(human_duration(30), "30s");
        assert_eq!(human_duration(90), "1m");
        assert_eq!(human_duration(7_200), "2h");
        assert_eq!(human_duration(172_800), "2d");
    }
}
