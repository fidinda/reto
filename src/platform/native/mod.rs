pub mod clock;
mod notifying;

impl<const SIZE: usize> notifying::Notifying for crate::face::local::LocalReceiver<SIZE> {}

pub mod shared;
pub mod tcp;
pub mod udp;

#[cfg(unix)]
pub mod unix;

pub mod forwarder;

#[cfg(feature = "sha2")]
use crate::{
    forwarder::InertMetrics,
    platform::{forwarder::BlockingForwarder, native::clock::MonotonicClock, sha::Sha256Hasher},
    tables::reference::ReferenceTables,
};

#[cfg(feature = "sha2")]
pub type DefaultForwarder =
    BlockingForwarder<MonotonicClock, Sha256Hasher, InertMetrics, ReferenceTables>;

#[cfg(feature = "sha2")]
impl Default for DefaultForwarder {
    fn default() -> Self {
        let clock = MonotonicClock::new();
        let hasher = Sha256Hasher::new();
        let metrics = InertMetrics {};
        let tables = ReferenceTables::default();
        DefaultForwarder::new(clock, hasher, metrics, tables)
    }
}
