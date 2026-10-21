use anyhow::Result;

use ac_net::config::Paths;

use crate::cmd::import::watch_for_a_code;
use crate::ops;
use crate::ops::lock::NodeLock;

const SCAN: &str = "scan this with the app on your phone";

/// Back this node's identity up to the companion app.
pub fn backup(paths: &Paths) -> Result<()> {
    // A running daemon holds the listener's port, so the phone would answer it, not us.
    let _lock = NodeLock::take(paths)?;
    ops::import::start_services(paths);

    let watching = watch_for_a_code(Some(SCAN));
    let done = ops::backup::backup(paths);
    watching.stop();
    done?;

    println!("backed up to the phone");
    Ok(())
}

/// Restore an identity from the companion app, then enrol with it: again with its server, or
/// with `invite` under the backup's username.
pub fn restore(paths: &Paths, invite: Option<&str>) -> Result<()> {
    let _lock = NodeLock::take(paths)?;
    ops::import::start_services(paths);

    let watching = watch_for_a_code(Some(SCAN));
    let recovered = ops::backup::restore(paths);
    watching.stop();
    let recovered = recovered?;
    println!("restored {} ({})", recovered.username, recovered.peer());

    let enrolled = match invite {
        Some(token) => {
            ops::join::from_token(paths, &recovered.identity, token, &recovered.username)?
        }
        None => ops::join::from_server(paths, &recovered.identity, &recovered.server)?,
    };
    println!("enrolled as {}", enrolled.username);
    println!("peer     {}", enrolled.peer);
    println!("server   {}", enrolled.server);
    println!("services {}", enrolled.service);
    Ok(())
}
