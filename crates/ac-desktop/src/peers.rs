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

pub fn read(paths: &Paths, report: Option<&StatusReport>) -> Vec<PeerItem> {
    let known = match ops::peer::list(paths) {
        Ok(known) => known,
        Err(e) => {
            tracing::warn!(error = %e, "could not list peers");
            return Vec::new();
        }
    };

    known
        .iter()
        .map(|entry| {
            let live = report
                .and_then(|report| report.peers.iter().find(|p| p.peer == entry.peer))
                .map(|p| view::describe_peer(p, report.map_or(0, |r| r.now)));

            let (tone, state) = live.unwrap_or_else(|| (view::QUIET, "no contact yet".to_owned()));

            PeerItem {
                name: entry.name.clone().into(),
                peer: entry.peer.to_string().into(),
                via: match entry.source {
                    Source::Contact => "contact",
                    Source::Group => "group",
                }
                .into(),
                state: state.into(),
                tone,
                removable: matches!(entry.source, Source::Contact),
            }
        })
        .collect()
}

pub fn apply(window: &MainWindow, items: Vec<PeerItem>) {
    window.set_peer_items(ModelRc::from(Rc::new(VecModel::from(items))));
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
            work::begin(&weak);
            work::action(
                &weak,
                move || {
                    let peer = ac_net::PeerId::from_str(&id)
                        .with_context(|| format!("{id} is not a peer id"))?;
                    let added = ops::peer::add(&paths, &peer, &label)?;
                    Ok(if added.was_new {
                        format!("added {} ({})", added.label, added.peer)
                    } else {
                        format!("relabelled {} to {}", added.peer, added.label)
                    })
                },
                move |window, outcome| work::finish(window, outcome, &nudge),
            );
        }
    });

    window.on_remove_peer({
        let paths = paths.clone();
        let nudge = nudge.clone();
        move |id| {
            let (paths, nudge) = (paths.clone(), nudge.clone());
            let id = id.to_string();
            work::begin(&weak);
            work::action(
                &weak,
                move || {
                    let peer = ac_net::PeerId::from_str(&id)
                        .with_context(|| format!("{id} is not a peer id"))?;
                    Ok(if ops::peer::remove(&paths, &peer)? {
                        format!("removed {peer}")
                    } else {
                        format!("no such contact: {peer}")
                    })
                },
                move |window, outcome| work::finish(window, outcome, &nudge),
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::tests::{home, somebody_else};

    #[test]
    fn a_contact_is_listed_as_one_and_can_be_removed() {
        let (_tmp, paths) = home("jonathan");
        let them = somebody_else();
        ops::peer::add(&paths, &them, "ana").unwrap();

        let items = read(&paths, None);

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "ana");
        assert_eq!(items[0].via, "contact");
        assert!(items[0].removable, "a contact is this node's to drop");
    }

    #[test]
    fn a_fellow_member_is_listed_through_the_group_and_cannot_be_removed() {
        let (_tmp, paths) = home("jonathan");
        let created = ops::group::create(&paths, "holiday").unwrap();
        let them = somebody_else();
        ops::group::add(&paths, &created.id.to_string(), &them, Some("ana")).unwrap();

        let items = read(&paths, None);
        let ana = items.iter().find(|p| p.name == "ana").unwrap();

        assert_eq!(ana.via, "group");
        assert!(!ana.removable);
    }

    #[test]
    fn a_peer_the_daemon_has_said_nothing_about_says_so() {
        let (_tmp, paths) = home("jonathan");
        ops::peer::add(&paths, &somebody_else(), "ana").unwrap();

        let items = read(&paths, None);

        assert_eq!(items[0].state, "no contact yet");
        assert_eq!(items[0].tone, view::QUIET);
    }
}
