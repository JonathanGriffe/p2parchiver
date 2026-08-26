use std::collections::BTreeMap;

use ac_groups::store::{Groups, State};
use ac_net::PeerId;
use anyhow::{Context, Result};

use crate::contacts::Contacts;

/// Why we know a name for this peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Contact,
    Group,
}

/// One peer, and the best name we have for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known {
    pub peer: PeerId,
    pub name: String,
    pub source: Source,
}

/// Every peer this node has a name for, ordered by name then peer id.
pub fn everyone(contacts: &Contacts, groups: &Groups, me: PeerId) -> Result<Vec<Known>> {
    let mut known: BTreeMap<PeerId, Known> = BTreeMap::new();

    for row in groups.list().context("listing groups")? {
        if row.state != State::Active {
            continue;
        }
        let members = groups
            .members(row.id)
            .with_context(|| format!("reading members of {}", row.id.short()))?;
        if !members.contains(&me) {
            continue;
        }

        for member in members.iter() {
            if member.peer == me {
                continue;
            }
            known.entry(member.peer).or_insert_with(|| Known {
                peer: member.peer,
                name: member.username.clone(),
                source: Source::Group,
            });
        }
    }

    for contact in contacts.list().context("listing contacts")? {
        known.insert(
            contact.peer,
            Known {
                peer: contact.peer,
                name: contact.label,
                source: Source::Contact,
            },
        );
    }

    let mut out: Vec<Known> = known.into_values().collect();
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.peer.cmp(&b.peer)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_groups::chain::Op;
    use libp2p::identity::Keypair;

    const AT: i64 = 1_000_000;

    fn key() -> Keypair {
        Keypair::generate_ed25519()
    }

    fn peer_of(key: &Keypair) -> PeerId {
        key.public().to_peer_id()
    }

    /// A store where `me` admins one group, plus the members added to it.
    fn group_with(me: PeerId, admin: &Keypair, members: &[(PeerId, &str)]) -> Groups {
        let mut groups = Groups::in_memory(me).unwrap();
        let id = groups.create(admin, "family", "admin", AT).unwrap();
        for (peer, username) in members {
            groups
                .author(
                    admin,
                    id,
                    Op::Add {
                        peer: peer.to_base58(),
                        username: (*username).to_owned(),
                    },
                    AT,
                )
                .unwrap();
        }
        groups
    }

    #[test]
    fn group_members_appear_without_being_added() {
        let admin = key();
        let me = peer_of(&admin);
        let bob = peer_of(&key());

        let groups = group_with(me, &admin, &[(bob, "bob")]);
        let contacts = Contacts::in_memory().unwrap();

        let known = everyone(&contacts, &groups, me).unwrap();
        assert_eq!(
            known,
            vec![Known {
                peer: bob,
                name: "bob".to_owned(),
                source: Source::Group,
            }]
        );
    }

    #[test]
    fn a_contact_outranks_a_membership_and_appears_once() {
        // The label was typed by this node's user; the username is whatever that group's admin
        // wrote. Preferring the username would let a remote admin rename an entry in someone
        // else's address book.
        let admin = key();
        let me = peer_of(&admin);
        let bob = peer_of(&key());

        let groups = group_with(me, &admin, &[(bob, "bob-from-the-log")]);
        let contacts = Contacts::in_memory().unwrap();
        contacts.add(&bob, "bobs-laptop").unwrap();

        let known = everyone(&contacts, &groups, me).unwrap();
        assert_eq!(known.len(), 1, "one row, not two");
        assert_eq!(known[0].name, "bobs-laptop");
        assert_eq!(known[0].source, Source::Contact);
    }

    #[test]
    fn we_are_never_listed_among_our_own_contacts() {
        let admin = key();
        let me = peer_of(&admin);
        let groups = group_with(me, &admin, &[]);

        assert!(
            everyone(&Contacts::in_memory().unwrap(), &groups, me)
                .unwrap()
                .is_empty(),
            "the admin is in the fold of their own group, and must not be listed"
        );
    }

    #[test]
    fn a_group_we_have_left_stops_contributing_people() {
        // Leaving means we no longer share anything with them. Continuing to list them would
        // make `leave` a purely cosmetic act in the one place a person actually looks.
        let admin = key();
        let me = peer_of(&admin);
        let bob = peer_of(&key());

        let mut groups = group_with(me, &admin, &[(bob, "bob")]);
        let id = groups.list().unwrap()[0].id;
        assert_eq!(
            everyone(&Contacts::in_memory().unwrap(), &groups, me)
                .unwrap()
                .len(),
            1
        );

        groups.set_state(id, State::Left).unwrap();

        assert!(
            everyone(&Contacts::in_memory().unwrap(), &groups, me)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_contact_survives_leaving_the_group_they_were_also_in() {
        // The two facts are independent: the membership went away, the hand-written row did
        // not. It just stops claiming to be a group name.
        let admin = key();
        let me = peer_of(&admin);
        let bob = peer_of(&key());

        let mut groups = group_with(me, &admin, &[(bob, "bob")]);
        let id = groups.list().unwrap()[0].id;
        let contacts = Contacts::in_memory().unwrap();
        contacts.add(&bob, "bobs-laptop").unwrap();

        groups.set_state(id, State::Left).unwrap();

        let known = everyone(&contacts, &groups, me).unwrap();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].source, Source::Contact);
        assert_eq!(known[0].name, "bobs-laptop");
    }

    #[test]
    fn listing_is_ordered_by_name() {
        let admin = key();
        let me = peer_of(&admin);
        let (a, b, c) = (peer_of(&key()), peer_of(&key()), peer_of(&key()));

        let groups = group_with(me, &admin, &[(a, "carol"), (b, "alice"), (c, "bob")]);
        let names: Vec<String> = everyone(&Contacts::in_memory().unwrap(), &groups, me)
            .unwrap()
            .into_iter()
            .map(|k| k.name)
            .collect();

        assert_eq!(names, ["alice", "bob", "carol"]);
    }
}
