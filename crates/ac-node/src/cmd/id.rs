use anyhow::{Context, Result};

use ac_net::config::Paths;
use ac_net::identity::{Identity, Origin};

pub fn run(paths: &Paths) -> Result<()> {
    let key_path = paths.identity_file();
    let (identity, origin) = Identity::load_or_generate(&key_path)
        .with_context(|| format!("loading identity from {}", key_path.display()))?;

    if origin == Origin::Generated {
        tracing::info!(path = %key_path.display(), "generated a new identity");
    }

    println!("{}", identity.peer_id());
    Ok(())
}
