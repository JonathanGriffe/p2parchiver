use std::thread::JoinHandle;

use ac_net::config::Paths;
use ac_node::daemon;
use ac_node::ops;
use anyhow::{Context, Result};
use tokio::sync::oneshot;

pub struct Node {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<()>>>,
}

impl Node {
    pub fn start(paths: Paths) -> Result<Self> {
        let (stop, stopped) = oneshot::channel();

        let thread = std::thread::Builder::new()
            .name("ac-node".to_owned())
            .spawn(move || run(paths, stopped))
            .context("starting the node thread")?;

        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Ask the daemon to stop and wait for it. Safe to call more than once.
    pub fn stop(&mut self) -> Result<()> {
        drop(self.stop.take());

        match self.thread.take() {
            Some(thread) => match thread.join() {
                Ok(result) => result,
                Err(_) => anyhow::bail!("the node thread panicked"),
            },
            None => Ok(()),
        }
    }
}

/// Run the daemon on the calling thread until it ends by itself, which is what Ctrl-C does.
pub fn run_here(paths: Paths) -> Result<()> {
    let (_stop, stopped) = oneshot::channel();
    run(paths, stopped)
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            tracing::warn!(error = %e, "the node did not stop cleanly");
        }
    }
}

fn run(paths: Paths, stopped: oneshot::Receiver<()>) -> Result<()> {
    let (identity, config) = ops::startup(&paths)?;

    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;

    runtime.block_on(async {
        tokio::select! {
            result = daemon::run(&identity, &config, &paths, &[]) => result,
            _ = stopped => {
                tracing::info!("stopping the node");
                Ok(())
            }
        }
    })
}
