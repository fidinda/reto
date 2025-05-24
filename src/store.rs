use core::future::Future;

use crate::{Name, Timestamp};

// Evict unsolicited first, then stale, then fresh.

// NFD has three FIFO queues for these.

// Stores items with full names (+ digest/freshness, then)
// Can probably do with RC?
// They just store in what probably is a BTreeSet, or smth.

// Can do custom Ord: store byte lengths of names, compare those,
// If not -> by digest stored separately!

// But: LRU (least recently used) policy could be better/simpler?
// Just every time we insert OR respond we move the entry to the last place in
// the eviction queue.

pub trait ContentStore {
    type Error;

    fn insert<'a, 'b>(
        &'b mut self,
        name: Name<'a>,
        digest: [u8; 32],
        freshness_deadline: Timestamp,
        packet: &'a [u8],
    ) -> impl Future<Output = Result<(), Self::Error>>;

    fn get<'a, 'b>(
        &'b self,
        name: Name<'a>,
        can_be_prefix: bool,
        freshness_requirement: Option<Timestamp>,
    ) -> impl Future<Output = Result<Option<&'b [u8]>, Self::Error>>;
}
