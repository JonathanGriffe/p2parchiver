use anyhow::{Result, bail};

use ac_import::companion::SCAN;
use ac_net::config::Paths;

use crate::cmd::join::print_enrolled;
use crate::cmd::prompt::watch_for_a_code;
use crate::ops;
use crate::ops::lock::NodeLock;

/// Back this node's identity up to every paired phone.
pub fn backup(paths: &Paths) -> Result<()> {
    println!("{}", ops::backup::backup(paths)?);
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
    let Some(recovered) = recovered? else {
        bail!("the restore was stopped");
    };
    println!("restored {} ({})", recovered.username, recovered.peer());

    let enrolled = match invite {
        Some(token) => {
            ops::join::from_token(paths, &recovered.identity, token, &recovered.username)?
        }
        None => ops::join::from_server(paths, &recovered.identity, &recovered.server)?,
    };
    print_enrolled(&enrolled);
    Ok(())
}
