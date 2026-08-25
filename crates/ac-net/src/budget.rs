use std::collections::HashMap;

use libp2p::PeerId;

/// Requests one peer may have answered between two ticks.
#[derive(Debug)]
pub struct TickBudget {
    per_tick: u32,
    spent: HashMap<PeerId, u32>,
}

impl TickBudget {
    pub fn new(per_tick: u32) -> Self {
        Self {
            per_tick,
            spent: HashMap::new(),
        }
    }

    /// Take one answer's worth of this peer's allowance, or refuse.
    pub fn spend(&mut self, peer: PeerId) -> bool {
        let spent = self.spent.entry(peer).or_insert(0);
        if *spent >= self.per_tick {
            return false;
        }
        *spent += 1;
        true
    }

    /// A new tick: everyone starts again.
    pub fn reset(&mut self) {
        self.spent.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_gets_exactly_its_allowance() {
        let mut budget = TickBudget::new(3);
        let p = PeerId::random();

        assert!((0..3).all(|_| budget.spend(p)));
        assert!(!budget.spend(p), "the fourth is refused");
    }

    #[test]
    fn one_peer_spending_out_does_not_touch_another() {
        let mut budget = TickBudget::new(1);
        let (a, b) = (PeerId::random(), PeerId::random());

        assert!(budget.spend(a));
        assert!(!budget.spend(a));
        assert!(
            budget.spend(b),
            "the allowance is per peer, not a shared pool"
        );
    }

    #[test]
    fn a_tick_gives_it_back() {
        let mut budget = TickBudget::new(1);
        let p = PeerId::random();

        assert!(budget.spend(p));
        assert!(!budget.spend(p));

        budget.reset();
        assert!(budget.spend(p));
    }

    #[test]
    fn nothing_is_owed_to_a_peer_that_never_asked() {
        let mut budget = TickBudget::new(2);
        budget.reset();
        assert!(
            budget.spend(PeerId::random()),
            "and a stranger still gets its own"
        );
    }
}
