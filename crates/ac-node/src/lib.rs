#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod cmd;
pub mod daemon;

// puts them in a signature, so they stay in.
mod blob;
mod contacts;
mod directory;
mod file_link;
mod group_link;
mod peer_link;
mod status;
mod throttle;

pub const DEFAULT_LOG: &str = "ac=info,ac_net=info,libp2p=warn";
