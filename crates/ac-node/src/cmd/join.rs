use anyhow::Result;

use ac_net::config::Paths;

use crate::ops;

pub fn run(paths: &Paths, token: &str, username: &str) -> Result<()> {
    let enrolled = ops::join::from_token(paths, token, username)?;

    println!("enrolled as {}", enrolled.username);
    println!("peer     {}", enrolled.peer);
    println!("server   {}", enrolled.server);
    println!("services {}", enrolled.service);
    println!(
        "attested for {}h, renewed automatically while `ac run` is up",
        enrolled.attested_for
    );
    println!();
    println!("That server is pinned now: a different one at the same address will fail to");
    println!("connect. The token you used is what said which server to expect.");

    Ok(())
}
