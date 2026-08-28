use anyhow::Result;
use libp2p::Multiaddr;

use ac_net::config::Paths;

use crate::ops;

pub fn run(paths: &Paths, server: &Multiaddr, code: &str, username: &str) -> Result<()> {
    let enrolled = ops::join::run(paths, server, code, username)?;

    println!("enrolled as {}", enrolled.username);
    println!("peer     {}", enrolled.peer);
    println!("server   {}", enrolled.server);
    println!("services {}", enrolled.service);
    println!(
        "attested for {}h, renewed automatically while `ac run` is up",
        enrolled.attested_for
    );
    println!();
    println!("Compare that server peer id against what `ac-server init` printed. It is");
    println!("pinned now: a different server at the same address will fail to connect.");

    Ok(())
}
