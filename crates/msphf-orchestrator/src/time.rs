use std::time::Duration;

/// Logical acceptance timestamp (tick counter) used to keep the pipeline time‑blind.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct AcceptInstant {
    ticks: u64,
}

impl AcceptInstant {
    pub const fn from_ticks(ticks: u64) -> Self {
        Self { ticks }
    }

    pub fn duration_since(self, earlier: AcceptInstant) -> Duration {
        Duration::from_secs(self.ticks.saturating_sub(earlier.ticks))
    }
}

/// Deterministic clock that advances once per accepted anchor.
#[derive(Copy, Clone, Debug)]
pub struct AcceptClock {
    next_tick: u64,
    last: AcceptInstant,
}

impl AcceptClock {
    pub fn new() -> Self {
        Self {
            next_tick: 0,
            last: AcceptInstant::from_ticks(0),
        }
    }

    pub fn now(&self) -> AcceptInstant {
        self.last
    }

    pub fn tick(&mut self) -> AcceptInstant {
        let instant = AcceptInstant::from_ticks(self.next_tick);
        self.next_tick = self.next_tick.saturating_add(1);
        self.last = instant;
        instant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_clock_saturates_instead_of_wrapping() {
        let mut clock = AcceptClock {
            next_tick: u64::MAX,
            last: AcceptInstant::from_ticks(u64::MAX - 1),
        };

        let first = clock.tick();
        let second = clock.tick();

        assert_eq!(first, AcceptInstant::from_ticks(u64::MAX));
        assert_eq!(second, AcceptInstant::from_ticks(u64::MAX));
        assert_eq!(clock.now(), AcceptInstant::from_ticks(u64::MAX));
        assert_eq!(
            clock
                .now()
                .duration_since(AcceptInstant::from_ticks(u64::MAX - 1)),
            Duration::from_secs(1)
        );
    }
}
