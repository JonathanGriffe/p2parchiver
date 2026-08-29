use std::rc::Rc;
use std::str::FromStr;

use ac_net::config::Paths;
use ac_node::ops;
use ac_node::ops::Source;
use ac_node::ops::peer::StatusReport;
use anyhow::Context;
use slint::{ComponentHandle, ModelRc, VecModel};

use crate::ui::{MainWindow, PeerItem};
use crate::view;
use crate::work::{self, Nudge};

/// The Peers page, in the two groups it is drawn in: people this node was told about, and
/// people it only ever met through a group.
#[derive(Default)]
pub struct Page {
    pub contacts: Vec<PeerItem>,
    pub discovered: Vec<PeerItem>,
}

pub fn read(paths: &Paths, report: Option<&StatusReport>) -> Page {
    let known = match ops::peer::list(paths) {
        Ok(known) => known,
        Err(e) => {
            tracing::warn!(error = %e, "could not list peers");
            return Page::default();
        }
    };

    let mut page = Page::default();
    for entry in &known {
        let live = report
            .and_then(|report| report.peers.iter().find(|p| p.peer == entry.peer))
            .map(|p| view::describe_peer(p, report.map_or(0, |r| r.now)));

        let (tone, state) = live.unwrap_or_else(|| (view::QUIET, "no contact yet".to_owned()));
        let contact = matches!(entry.source, Source::Contact);

        let item = PeerItem {
            // A name this node chose stands as it is; one it only overheard in a group is
            // marked, so the two are not read as equally trustworthy at a glance.
            name: match contact {
                true => entry.name.clone(),
                false => format!("~ {}", entry.name),
            }
            .into(),
            peer: entry.peer.to_string().into(),
            state: state.into(),
            tone,
        };

        match contact {
            true => page.contacts.push(item),
            false => page.discovered.push(item),
        }
    }
    page
}

pub fn apply(window: &MainWindow, page: Page) {
    window.set_peer_contacts(ModelRc::from(Rc::new(VecModel::from(page.contacts))));
    window.set_peer_discovered(ModelRc::from(Rc::new(VecModel::from(page.discovered))));
}

pub fn wire(window: &MainWindow, paths: &Paths, nudge: &Nudge) {
    let weak = window.as_weak();

    window.on_add_peer({
        let weak = weak.clone();
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |id, label| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let (id, label) = (id.to_string(), label.to_string());
            work::run(&weak, &nudge, move || {
                let peer = ac_net::PeerId::from_str(&id)
                    .with_context(|| format!("{id} is not a peer id"))?;
                let added = ops::peer::add(&paths, &peer, &label)?;
                Ok(if added.was_new {
                    format!("added {} ({})", added.label, added.peer)
                } else {
                    format!("relabelled {} to {}", added.peer, added.label)
                })
            });
        }
    });

    window.on_remove_peer({
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |id| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let id = id.to_string();
            work::run(&weak, &nudge, move || {
                let peer = ac_net::PeerId::from_str(&id)
                    .with_context(|| format!("{id} is not a peer id"))?;
                Ok(if ops::peer::remove(&paths, &peer)? {
                    format!("removed {peer}")
                } else {
                    format!("no such contact: {peer}")
                })
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::tests::{home, somebody_else};

    #[test]
    fn a_contact_is_listed_under_contacts_by_the_name_this_node_gave_them() {
        let (_tmp, paths) = home("jonathan");
        let them = somebody_else();
        ops::peer::add(&paths, &them, "ana").unwrap();

        let page = read(&paths, None);

        assert_eq!(page.contacts.len(), 1);
        assert_eq!(page.contacts[0].name, "ana", "no mark on a name we chose");
        assert!(page.discovered.is_empty());
    }

    #[test]
    fn a_fellow_member_is_listed_as_discovered_and_marked_as_overheard() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them, Some("ana")).unwrap();

        let page = read(&paths, None);

        assert!(page.contacts.is_empty(), "never told about them directly");
        let ana = page
            .discovered
            .iter()
            .find(|p| p.name.ends_with("ana"))
            .unwrap();
        assert_eq!(ana.name, "~ ana");
    }

    /// Adding someone as a contact is what promotes them out of the discovered list, so the
    /// same person must not appear in both.
    #[test]
    fn a_fellow_member_this_node_also_named_is_listed_once_as_a_contact() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them, Some("ana")).unwrap();
        ops::peer::add(&paths, &them, "ana").unwrap();

        let page = read(&paths, None);

        assert_eq!(page.contacts.len(), 1);
        assert_eq!(page.contacts[0].name, "ana");
        assert!(page.discovered.is_empty(), "not in both lists");
    }

    #[test]
    fn a_peer_the_daemon_has_said_nothing_about_says_so() {
        let (_tmp, paths) = home("jonathan");
        ops::peer::add(&paths, &somebody_else(), "ana").unwrap();

        let page = read(&paths, None);

        assert_eq!(page.contacts[0].state, "no contact yet");
        assert_eq!(page.contacts[0].tone, view::QUIET);
    }
}
