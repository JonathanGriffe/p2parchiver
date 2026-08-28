use anyhow::{Result, bail};
use slint::Weak;

use crate::ui::MainWindow;

pub struct Tray;

impl Tray {
    pub fn live(&self) -> super::Live {
        super::Live::new(false)
    }
}

pub fn spawn(_window: Weak<MainWindow>, _nudge: crate::work::Nudge) -> Result<Tray> {
    bail!("no tray backend for this platform")
}
