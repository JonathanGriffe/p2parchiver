//! The enrol dialog: which identity to enrol with, a new one or one restored from the phone,
//! then the server.

use std::sync::{Arc, Mutex};

use ac_net::config::Paths;
use ac_net::identity::Identity;
use ac_node::ops;
use ac_node::ops::backup::Recovered;
use ac_node::ops::join::Enrolled;
use anyhow::Result;
use slint::ComponentHandle;

use crate::settings::{self, Shared};
use crate::ui::{EnrolPhase, MainWindow};
use crate::view;
use crate::work::{self, Nudge};

/// An identity restored from the phone, held until enrolling with it, and lost with the app.
type Restored = Arc<Mutex<Option<Recovered>>>;

/// How the dialog enrols.
enum Enrol {
    /// With an invite, as `identity`, or as this node's own key for `None`.
    Token {
        token: String,
        username: String,
        identity: Option<Identity>,
    },
    /// Again with the server a restored identity enrolled with.
    Continue(Recovered),
}

pub fn wire(window: &MainWindow, paths: &Paths, node: &Shared, nudge: &Nudge) {
    let weak = window.as_weak();
    let restored: Restored = Arc::default();

    window.on_enrol_new({
        let weak = weak.clone();
        let restored = restored.clone();
        move || {
            *restored.lock().unwrap_or_else(|e| e.into_inner()) = None;
            if let Some(window) = weak.upgrade() {
                window.set_enrol_restored(false);
                window.set_enrol_error("".into());
                window.set_enrol_phase(EnrolPhase::Form);
            }
        }
    });

    window.on_enrol_restore({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        let restored = restored.clone();
        move || {
            let (paths, nudge, restored) = (paths.clone(), nudge.clone(), restored.clone());
            work::begin(&weak);
            if let Some(window) = weak.upgrade() {
                window.set_enrol_error("".into());
                window.set_enrol_phase(EnrolPhase::Restoring);
            }
            work::nudge_when_code_shows(&nudge);

            work::action(
                &weak,
                move || ops::backup::restore(&paths),
                move |window, outcome| {
                    match outcome {
                        Ok(Some(recovered)) => {
                            window.set_enrol_username(recovered.username.as_str().into());
                            window.set_enrol_restored(true);
                            *restored.lock().unwrap_or_else(|e| e.into_inner()) = Some(recovered);
                            window.set_enrol_phase(EnrolPhase::Form);
                        }
                        Ok(None) => window.set_enrol_phase(EnrolPhase::Identity),
                        Err(e) => {
                            window.set_enrol_error(format!("{e:#}").into());
                            window.set_enrol_phase(EnrolPhase::Identity);
                        }
                    }
                    work::quiet(window, &nudge);
                },
            );
        }
    });

    window.on_enrol_continue({
        let weak = weak.clone();
        let paths = paths.clone();
        let node = node.clone();
        let nudge = nudge.clone();
        let restored = restored.clone();
        move || {
            // Offered only once something has been restored.
            if let Some(recovered) = held(&restored) {
                let how = Enrol::Continue(recovered);
                enrol(&weak, &paths, &node, &nudge, &restored, how);
            }
        }
    });

    window.on_join({
        let paths = paths.clone();
        let node = node.clone();
        let nudge = nudge.clone();
        move |token, username| {
            let how = Enrol::Token {
                token: token.to_string(),
                username: username.to_string(),
                identity: held(&restored).map(|recovered| recovered.identity),
            };
            enrol(&weak, &paths, &node, &nudge, &restored, how);
        }
    });
}

/// The identity restored from the phone, if one is held.
fn held(restored: &Restored) -> Option<Recovered> {
    restored.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Enrol as the dialog asked.
fn enrol_with(paths: &Paths, how: Enrol) -> Result<Enrolled> {
    match how {
        Enrol::Continue(r) => ops::join::from_server(paths, &r.identity, &r.server),
        Enrol::Token {
            token,
            username,
            identity,
        } => {
            let identity = match identity {
                Some(identity) => identity,
                None => ops::identity(paths)?,
            };
            ops::join::from_token(paths, &identity, &token, &username)
        }
    }
}

/// Stop the node, enrol, and start the node again whatever the outcome.
fn enrol(
    weak: &slint::Weak<MainWindow>,
    paths: &Paths,
    node: &Shared,
    nudge: &Nudge,
    restored: &Restored,
    how: Enrol,
) {
    let (paths, node, nudge, kept) = (paths.clone(), node.clone(), nudge.clone(), restored.clone());
    work::begin(weak);
    if let Some(window) = weak.upgrade() {
        window.set_enrol_phase(EnrolPhase::Working);
        window.set_enrol_error("".into());
    }

    let reload = paths.clone();
    work::action(
        weak,
        move || {
            settings::stop(&node)?;
            let enrolled = enrol_with(&paths, how);
            // Started again whichever way it went: a node left stopped by a
            // refusal would look like the app itself had given up.
            settings::start(&node, &paths)?;
            enrolled
        },
        move |window, outcome| {
            if outcome.is_ok() {
                *kept.lock().unwrap_or_else(|e| e.into_inner()) = None;
                window.set_enrol_restored(false);
            }
            settings::load(window, &reload);
            // The window reads these once at startup, and enrolling is the one thing that
            // changes them, the peer id too after a restore: without this the name and the
            // server stay blank until the app is opened again.
            if let Err(e) = view::describe_node(window, &reload) {
                tracing::warn!(error = %e, "could not re-read this node's details");
            }

            match &outcome {
                Ok(enrolled) => {
                    // The dialog has the name in front of someone who just typed it; the
                    // rest is on the Status page behind it.
                    window.set_enrol_summary(format!("Enrolled as {}.", enrolled.username).into());
                    window.set_enrol_phase(EnrolPhase::Done);
                }
                Err(e) => {
                    // `{:#}` so the server's reason comes through, not just the outermost
                    // context.
                    window.set_enrol_error(format!("{e:#}").into());
                    window.set_enrol_phase(EnrolPhase::Form);
                }
            }

            if window.get_show_enrol() {
                // The dialog is saying it; the shared line would only repeat it, out of
                // sight behind the dialog.
                work::quiet(window, &nudge);
            } else {
                // Nobody is looking at a dialog, so the one line has to carry it.
                let said = outcome.map(|enrolled| {
                    format!(
                        "Enrolled as {} with {}, attested for {}h. That server is pinned now.",
                        enrolled.username, enrolled.server, enrolled.attested_for
                    )
                });
                work::finish(window, said, &nudge);
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use i_slint_backend_testing::ElementHandle;

    use super::*;

    /// The dialog stays up for the whole of enrolling, so what it shows is the only thing
    /// saying whether anything is happening. Drawn into memory, so this needs no display.
    #[test]
    fn the_enrol_dialog_shows_one_thing_at_a_time() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_show_enrol(true);

        let showing = |label: &str| ElementHandle::find_by_accessible_label(&window, label).count();
        let enrolling = "Enrolling. The node stops and starts again, which takes a moment.";

        window.set_enrol_phase(EnrolPhase::Identity);
        assert_eq!(showing("New identity"), 1, "first, which identity");
        assert_eq!(showing("Restore from phone"), 1);
        assert_eq!(showing("Not now"), 1);
        assert_eq!(showing("Enrol"), 0, "the server comes after");

        window.set_enrol_phase(EnrolPhase::Restoring);
        assert_eq!(showing("Cancel"), 1, "waiting on the phone can be given up");
        assert_eq!(showing("New identity"), 0);
        assert_eq!(showing("Not now"), 0);

        window.set_enrol_phase(EnrolPhase::Form);
        assert_eq!(showing("Enrol"), 1, "the form offers to enrol");
        assert_eq!(showing("Continue"), 0, "with nothing restored to continue");
        assert_eq!(showing("Not now"), 1);
        assert_eq!(showing(enrolling), 0);
        assert_eq!(showing("Close"), 0);

        // A refusal comes back into the form, with the reason above it.
        window.set_enrol_error("that invite token is damaged".into());
        assert_eq!(showing("that invite token is damaged"), 1);
        assert_eq!(showing("Enrol"), 1, "and it can be tried again");

        window.set_enrol_phase(EnrolPhase::Working);
        assert_eq!(showing(enrolling), 1);
        assert_eq!(showing("Enrol"), 0, "nothing to press while it runs");
        assert_eq!(showing("Not now"), 0);
        assert_eq!(
            showing("that invite token is damaged"),
            0,
            "the last failure is not still on screen while the next attempt runs"
        );

        window.set_enrol_phase(EnrolPhase::Done);
        window.set_enrol_summary("Enrolled as alice.".into());
        assert_eq!(showing("Successfully enrolled"), 1, "the title says so too");
        assert_eq!(showing("Enrol this node"), 0);
        assert_eq!(showing("Enrolled as alice."), 1);
        assert_eq!(showing("Close"), 1);
        assert_eq!(showing("Enrol"), 0, "there is nothing left to enrol");

        ElementHandle::find_by_accessible_label(&window, "Close")
            .next()
            .unwrap()
            .invoke_accessible_default_action();
        assert!(!window.get_show_enrol(), "Close puts the dialog away");
    }

    /// A restored identity can enrol again with its own server, under the name it came with.
    #[test]
    fn a_restored_identity_can_continue_under_its_own_name() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_show_enrol(true);
        window.set_enrol_phase(EnrolPhase::Form);

        let continued = Rc::new(std::cell::Cell::new(false));
        window.on_enrol_continue({
            let continued = continued.clone();
            move || continued.set(true)
        });

        window.set_enrol_restored(true);
        window.set_enrol_username("alice".into());
        let field = ElementHandle::find_by_element_id(&window, "EnrolDialog::who")
            .next()
            .unwrap();
        assert_eq!(field.accessible_value().unwrap(), "alice", "prefilled");

        let button = ElementHandle::find_by_accessible_label(&window, "Continue")
            .next()
            .expect("offered once restored");
        button.invoke_accessible_default_action();
        assert!(continued.get());
    }

    /// A refusal over the username should not cost someone the token they pasted, so the
    /// fields have to survive the trip out to the phase that has no fields at all.
    #[test]
    fn what_was_typed_survives_a_failed_attempt() {
        i_slint_backend_testing::init_no_event_loop();
        let window = MainWindow::new().unwrap();
        window.set_show_enrol(true);
        window.set_enrol_phase(EnrolPhase::Form);

        let field = |id: &str| {
            ElementHandle::find_by_element_id(&window, id)
                .next()
                .unwrap()
        };
        field("EnrolDialog::token").set_accessible_value("ac1thetoken");
        field("EnrolDialog::who").set_accessible_value("alice");

        window.set_enrol_phase(EnrolPhase::Working);
        window.set_enrol_phase(EnrolPhase::Form);

        assert_eq!(
            field("EnrolDialog::token").accessible_value().unwrap(),
            "ac1thetoken"
        );
        assert_eq!(
            field("EnrolDialog::who").accessible_value().unwrap(),
            "alice"
        );
    }
}
