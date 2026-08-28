use anyhow::{Context, Result};
use ksni::blocking::TrayMethods;
use ksni::menu::{CheckmarkItem, MenuItem, StandardItem};
use slint::Weak;

use super::{Live, icon};
use crate::ui::MainWindow;

pub struct Tray {
    #[allow(dead_code)]
    handle: ksni::blocking::Handle<Item>,
    live: Live,
}

impl Tray {
    pub fn live(&self) -> Live {
        self.live.clone()
    }
}

struct Item {
    window: Weak<MainWindow>,
    /// Mirrors the recorded entry, re-read after every change rather than assumed.
    autostart: bool,
    live: Live,
}

impl ksni::Tray for Item {
    fn id(&self) -> String {
        "archiverclient".to_owned()
    }

    fn title(&self) -> String {
        "ArchiverClient".to_owned()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        icon::SIZES
            .into_iter()
            .map(|size| ksni::Icon {
                width: size as i32,
                height: size as i32,
                data: icon::argb(size),
            })
            .collect()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        super::show(&self.window);
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        tracing::warn!(
            ?reason,
            "the tray host is gone; the window will no longer hide on close"
        );
        self.live.set(false);
        true
    }

    fn watcher_online(&self) {
        tracing::info!("the tray host is back");
        self.live.set(true);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Open".into(),
                activate: Box::new(|item: &mut Self| super::show(&item.window)),
                ..Default::default()
            }
            .into(),
            CheckmarkItem {
                label: "Start at login".into(),
                checked: self.autostart,
                activate: Box::new(|item: &mut Self| item.toggle_autostart()),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|_: &mut Self| super::quit()),
                ..Default::default()
            }
            .into(),
        ]
    }
}

impl Item {
    fn toggle_autostart(&mut self) {
        super::set_autostart(!self.autostart);
        self.autostart = crate::autostart::state().is_ok_and(|s| s.is_on());
    }
}

pub fn spawn(window: Weak<MainWindow>) -> Result<Tray> {
    let autostart = crate::autostart::state().is_ok_and(|s| s.is_on());
    let live = Live::new(true);
    let handle = Item {
        window,
        autostart,
        live: live.clone(),
    }
    .spawn()
    .context("registering a StatusNotifierItem")?;
    Ok(Tray { handle, live })
}
