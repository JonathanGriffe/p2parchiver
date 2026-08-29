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

/// How a name is shown, wherever a person appears.
///
/// A name this node chose stands as it is. A name the person chose for themselves is marked,
/// because nothing verifies it: it is what they say they are called, not who they are.
pub fn display_name(name: Option<&str>, source: Source, peer: &ac_net::PeerId) -> String {
    match (name, source) {
        (Some(name), Source::Contact) => name.to_owned(),
        (Some(name), Source::Group) => format!("~ {name}"),
        // Nobody has told us anything, so there is nothing to mark up. A short id is not a
        // claim, and dressing it as one would say they call themselves "12D3KooW".
        (None, _) => peer.to_base58()[..8].to_owned(),
    }
}

pub fn read(known: &[ops::Known], report: Option<&StatusReport>) -> Page {
    let mut page = Page::default();
    for entry in known {
        let live = report
            .and_then(|report| report.peers.iter().find(|p| p.peer == entry.peer))
            .map(|p| view::describe_peer(p, report.map_or(0, |r| r.now)));

        let (tone, state) = live.unwrap_or_else(|| (view::QUIET, "no contact yet".to_owned()));
        let contact = matches!(entry.source, Source::Contact);

        let item = PeerItem {
            name: display_name(entry.name.as_deref(), entry.source, &entry.peer).into(),
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

    /// The page as the poller builds it.
    fn page(paths: &Paths) -> Page {
        read(&ops::peer::list(paths).unwrap_or_default(), None)
    }

    #[test]
    fn a_contact_is_listed_under_contacts_by_the_name_this_node_gave_them() {
        let (_tmp, paths) = home("jonathan");
        let them = somebody_else();
        ops::peer::add(&paths, &them, "ana").unwrap();

        let page = page(&paths);

        assert_eq!(page.contacts.len(), 1);
        assert_eq!(page.contacts[0].name, "ana", "no mark on a name we chose");
        assert!(page.discovered.is_empty());
    }

    #[test]
    fn a_fellow_member_is_listed_as_discovered_and_marked_as_overheard() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them).unwrap();

        let page = page(&paths);

        assert!(page.contacts.is_empty(), "never told about them directly");
        // They have published no standing, so there is no name to mark up: the short id is
        // the only thing this node actually knows about them.
        assert_eq!(page.discovered.len(), 1);
        assert_eq!(page.discovered[0].name, them.to_base58()[..8].to_owned());
    }

    /// Adding someone as a contact is what promotes them out of the discovered list, so the
    /// same person must not appear in both.
    #[test]
    fn a_fellow_member_this_node_also_named_is_listed_once_as_a_contact() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them).unwrap();
        ops::peer::add(&paths, &them, "ana").unwrap();

        let page = page(&paths);

        assert_eq!(page.contacts.len(), 1);
        assert_eq!(page.contacts[0].name, "ana");
        assert!(page.discovered.is_empty(), "not in both lists");
    }

    #[test]
    fn a_peer_the_daemon_has_said_nothing_about_says_so() {
        let (_tmp, paths) = home("jonathan");
        ops::peer::add(&paths, &somebody_else(), "ana").unwrap();

        let page = page(&paths);

        assert_eq!(page.contacts[0].state, "no contact yet");
        assert_eq!(page.contacts[0].tone, view::QUIET);
    }
}
