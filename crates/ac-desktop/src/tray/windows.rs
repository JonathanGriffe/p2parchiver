use anyhow::{Context, Result};
use slint::Weak;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

use super::{Live, icon};
use crate::ui::MainWindow;
use crate::work::Nudge;

pub struct Tray {
    #[allow(dead_code)]
    icon: TrayIcon,
    #[allow(dead_code)]
    pump: slint::Timer,
}

impl Tray {
    pub fn live(&self) -> Live {
        Live::new(true)
    }
}

const PUMP: std::time::Duration = std::time::Duration::from_millis(100);

pub fn spawn(window: Weak<MainWindow>, nudge: Nudge) -> Result<Tray> {
    let image = tray_icon::Icon::from_rgba(icon::rgba(icon::NATIVE), icon::NATIVE, icon::NATIVE)
        .context("building the tray icon")?;

    let menu = Menu::new();
    let open = MenuItem::new("Open", true, None);
    let startup = CheckMenuItem::new(
        "Start at login",
        true,
        crate::autostart::state().is_ok_and(|s| s.is_on()),
        None,
    );
    let quit = MenuItem::new("Quit", true, None);
    menu.append(&open).context("building the tray menu")?;
    menu.append(&startup).context("building the tray menu")?;
    menu.append(&PredefinedMenuItem::separator())
        .context("building the tray menu")?;
    menu.append(&quit).context("building the tray menu")?;

    let (open_id, startup_id, quit_id) =
        (open.id().clone(), startup.id().clone(), quit.id().clone());

    let icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("ArchiverClient")
        .with_icon(image)
        .build()
        .context("adding an icon to the tray")?;

    let pump = slint::Timer::default();
    pump.start(slint::TimerMode::Repeated, PUMP, move || {
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == open_id {
                super::show(&window, &nudge);
            } else if event.id == startup_id {
                super::set_autostart(startup.is_checked());
                startup.set_checked(crate::autostart::state().is_ok_and(|s| s.is_on()));
            } else if event.id == quit_id {
                super::quit();
            }
        }
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::DoubleClick { .. } = event {
                super::show(&window, &nudge);
            }
        }
    });

    Ok(Tray { icon, pump })
}
