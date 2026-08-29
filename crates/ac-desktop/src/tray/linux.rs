use anyhow::{Context, Result};
use ksni::blocking::TrayMethods;
use ksni::menu::{MenuItem, StandardItem};
use slint::Weak;

use super::{Live, icon};
use crate::ui::MainWindow;
use crate::work::Nudge;

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
    nudge: Nudge,
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
        super::show(&self.window, &self.nudge);
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
                activate: Box::new(|item: &mut Self| super::show(&item.window, &item.nudge)),
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

pub fn spawn(window: Weak<MainWindow>, nudge: Nudge) -> Result<Tray> {
    let live = Live::new(true);
    let handle = Item {
        window,
        nudge,
        live: live.clone(),
    }
    .spawn()
    .context("registering a StatusNotifierItem")?;
    Ok(Tray { handle, live })
}
