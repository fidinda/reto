use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::clock::{Clock, Timestamp};

mod notifying;

pub mod local;
pub mod tcp;

pub mod forwarder;

#[cfg(feature = "websocket")]
pub mod websocket;

pub struct MonotonicClock {
    reference: Instant,
    reference_ms: u64,
}

impl MonotonicClock {
    pub fn new() -> Self {
        let reference_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| u64::try_from(d.as_millis()).ok())
            .flatten()
            .unwrap_or(u64::MAX);
        let reference = Instant::now();
        Self {
            reference,
            reference_ms,
        }
    }
}

impl Clock for MonotonicClock {
    fn now(&mut self) -> Timestamp {
        let millis = u64::try_from(Instant::now().duration_since(self.reference).as_millis())
            .unwrap_or(u64::MAX);

        Timestamp {
            ms_since_1970: self.reference_ms.saturating_add(millis),
        }
    }
}


#[cfg(feature = "sha2")]
use crate::{forwarder::InertMetrics, platform::{forwarder::BlockingForwarder, sha::Sha256Hasher}, tables::reference::ReferenceTables};

#[cfg(feature = "sha2")]
type DefaultForwarder = BlockingForwarder<MonotonicClock, Sha256Hasher, InertMetrics, ReferenceTables>;

#[cfg(feature = "sha2")]
impl Default for DefaultForwarder {
    fn default() -> Self {
        let clock = MonotonicClock::new();
        let hasher = Sha256Hasher::new();
        let metrics = InertMetrics{};
        let tables = ReferenceTables::default();
        DefaultForwarder::new(clock, hasher, metrics, tables)
    }
}
