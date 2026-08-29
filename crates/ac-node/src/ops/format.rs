//! Turning values into the words a person reads. Shared, so the CLI and the UI say the same
//! thing about the same number.

use ac_groups::chain::Op;
pub use ac_groups::store::State;

use super::now;

/// How long ago a timestamp was, in the largest useful unit.
pub fn ago(at: i64) -> String {
    let seconds = now() - at;
    match seconds {
        s if s < 0 => "in the future".to_owned(),
        s if s < 60 => "just now".to_owned(),
        s if s < 3_600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3_600),
        s => format!("{}d ago", s / 86_400),
    }
}

/// Sizes at a glance. Decimal units, because that is what the drive was sold as and what the
/// desktop's own file manager shows beside it.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1000.0 && unit < UNITS.len() - 1 {
        size /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

pub fn state_name(state: State) -> &'static str {
    match state {
        State::Pending => "invited",
        State::Active => "member",
        State::Left => "left",
    }
}

/// One entry of a group's log, as a sentence.
pub fn describe(op: &Op) -> String {
    match op {
        Op::Create { name, admin, .. } => format!("created {name:?} by {admin}"),
        Op::Add { peer, username } => format!("added {username} ({peer})"),
        Op::Remove { peer } => format!("removed {peer}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_read_in_the_largest_useful_unit() {
        let t = now();
        assert_eq!(ago(t), "just now");
        assert_eq!(ago(t - 300), "5m ago");
        assert_eq!(ago(t - 7_200), "2h ago");
        assert_eq!(ago(t - 172_800), "2d ago");
        assert_eq!(ago(t + 600), "in the future");
    }

    #[test]
    fn sizes_read_the_way_a_person_would_say_them() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(999), "999 B", "still bytes right up to the unit");
        assert_eq!(human_size(1_000), "1.0 KB");
        assert_eq!(human_size(1_500), "1.5 KB");
        assert_eq!(human_size(4_000_000), "4.0 MB");
        assert_eq!(human_size(500_000_000_000), "500.0 GB");
    }
}
