use core::{cmp::Ordering, num::NonZeroU16};

use alloc::{boxed::Box, collections::btree_map::BTreeMap, vec::Vec};

use crate::{
    clock::Timestamp,
    forwarder::FaceToken,
    name::{Name, NameComponent},
    tables::Tables,
};

// The reference implementation of Tables encodes the following forwarding strategy:
// 1. The incoming interest is checked for validity of name and the presence of nonce
//      and is dropped if some irregularities are found.
// 2. If it is (probabilistically) in the Dead Nonce List we drop the interest immediately
//      (in case of a false positive the source will retransmit it with a new nonce).
// 3. If we are here, the interest needs to be admitted by the PIT, so we get or create a
//      PIT entry correspoding to the interest's full name. Then we have options:
//      -- If the PIT entry is new we store the interest and notify lowest-cost face
//          in the FIB entry corrseponding to the longest match.
//      -- If the PIT entry is not new and there is an interest registed from _any_ face
//          with the same nonce as this packet, we treat it as a loop and drop the packet.
//      -- Otherwise, this is treated as a new interest and is sent to the _next_ face
//          in terms of cost at the longest prefix (or then also on higher levels ordered
//          by costs within level), unless it was sent recently. Here "recently" is an
//          exponential backoff that starts at 10 ms and doubles until the maximum of 250 ms

// Data satisfaction
// When the data arrives we want to check all of the PIT entries it can satisfy.
// The name of the data is it's "exact" name (excluding the digest component) and
//  it will be matched to:
//  - exact name "normal" PITs
//  - full name "normal" PITs that have the same digest
//  - all the PITs along the way that have the "can_be_prefix" flag
// After a PIT is satisfied we take out all the faces that were registered,
//  add the nonces to Dead Nonce List, and rest the pit entry (possibly also cleaning it up).

pub struct ReferenceTables {
    root: TableEntry,
    dead_nonce_list: DeadNonceList,
    data_cache_duration_ms: u64,
    face_scratchpad: Vec<(u32, FaceToken)>,
}

impl ReferenceTables {
    pub fn new(data_cache_duration_ms: u32, dead_nonce_duration_ms: u32) -> Self {
        Self {
            root: TableEntry::new(),
            dead_nonce_list: DeadNonceList::new(dead_nonce_duration_ms as u64),
            data_cache_duration_ms: data_cache_duration_ms as u64,
            face_scratchpad: Default::default(),
        }
    }

    fn return_faces(&self) -> impl Iterator<Item = FaceToken> + '_ {
        return self.face_scratchpad.iter().map(|x| x.1);
    }
}

impl Tables for ReferenceTables {
    fn unregister_face(&mut self, face: FaceToken) {
        self.root
            .unregister_prefix(&mut None.into_iter(), face, true, true);
    }

    fn prune_if_needed(&mut self, now: Timestamp) {
        self.root
            .prune_if_needed(Name::new(), now, &mut self.dead_nonce_list);
        self.dead_nonce_list.prune(now);

        // TODO: Maybe need to have metrics here? Or return number of removed data/intrests

        // TODO: we could check the CS count here and if it is too big
        //  could prune with now = (actual_now - 0.5 * data_cache_duration_ms), then 0.75, etc.

        // LRU cache policy LRU cache policy implements the Least Recently Used cache replacement algorithm, which discards the least recently used items first. LRU evicts upon every insertion, because its performance is more predictable; the alternative, periodic cleanup of a batch of entries, can cause jitter in packet forwarding.
        // LRU uses one queue to keep track of data usage in CS. The Table iterator is stored in the queue. At any time, when an entry is used or refreshed, its Table iterator is relocated to the tail of the queue. Also, when an entry is newly inserted, its Table iterator is pushed at the tail of the queue. When an entry needs to be evicted, its Table iterator is erased from the head of its queue, and the entry is erased from the Table.
        // Could be done if we store Rc<child> and store those in some queue
    }

    fn register_prefix(&mut self, name_prefix: Name<'_>, face: FaceToken, cost: u32) {
        self.root
            .register_prefix(&mut name_prefix.components(), face, cost);
    }

    fn unregister_prefix(&mut self, name_prefix: Name<'_>, face: FaceToken) -> bool {
        self.root
            .unregister_prefix(&mut name_prefix.components(), face, false, false)
    }

    fn register_interest(
        &mut self,
        name: Name<'_>,
        can_be_prefix: bool,
        interest_lifetime: Option<u64>,
        nonce: [u8; 4],
        reply_to: FaceToken,
        now: Timestamp,
    ) -> impl Iterator<Item = FaceToken> {
        self.face_scratchpad.clear();

        if name.component_count() == 0 {
            return self.return_faces();
        }

        if self.dead_nonce_list.contains(name, nonce) {
            return self.return_faces();
        }

        let deadline = match interest_lifetime {
            Some(ms) => now.adding(ms),
            None => now.adding(DEFAULT_DEADLINE_INCREMENT_MS),
        };

        self.root.register_interest(
            name,
            &mut name.components(),
            can_be_prefix,
            reply_to,
            now,
            deadline,
            nonce,
            &mut self.dead_nonce_list,
            &mut self.face_scratchpad,
        );

        return self.return_faces();
    }

    fn satisfy_interests<H>(
        &mut self,
        name: Name<'_>,
        now: Timestamp,
        digest_computation: &mut H,
    ) -> impl Iterator<Item = FaceToken>
    where
        H: FnMut() -> [u8; 32],
    {
        self.face_scratchpad.clear();
        self.root.satisfy_interests(
            name,
            &mut name.components(),
            now,
            &mut self.dead_nonce_list,
            &mut self.face_scratchpad,
            digest_computation,
        );

        // Only want distinct faces
        self.face_scratchpad.sort();
        self.face_scratchpad.dedup();
        return self.return_faces();
    }

    fn insert_data<'a>(
        &mut self,
        name: Name<'a>,
        digest: [u8; 32],
        freshness: u64,
        now: Timestamp,
        packet: &'a [u8],
    ) {
        self.root.insert_data(
            &mut name.components(),
            digest,
            freshness,
            now,
            self.data_cache_duration_ms,
            packet,
        );
    }

    fn get_data<'a>(
        &mut self,
        name: Name<'a>,
        can_be_prefix: bool,
        must_be_fresh: bool,
        now: Timestamp,
    ) -> Option<&[u8]> {
        self.root.get_data(
            &mut name.components(),
            can_be_prefix,
            must_be_fresh,
            now,
            self.data_cache_duration_ms,
        )
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
struct EncodedComponent {
    typ: NonZeroU16,
    bytes: Box<[u8]>,
}

impl EncodedComponent {
    fn from_named_component<'a>(component: NameComponent<'a>) -> Self {
        Self {
            typ: component.typ,
            bytes: Box::from(component.bytes),
        }
    }

    fn compare_to_name_component<'a>(&self, component: NameComponent<'a>) -> Ordering {
        if self.typ == component.typ {
            return self.bytes.as_ref().cmp(component.bytes);
        }
        self.typ.cmp(&component.typ)
    }
}

struct TableEntry {
    // Ordered by cost
    fib: Vec<FibEntry>,
    pit_normal: PitEntry,
    pit_prefix: PitEntry,
    data: Option<DataEntry>,
    // Ordered by EncodedComponent
    children: Vec<(EncodedComponent, TableEntry)>,
}

impl TableEntry {
    fn new() -> Self {
        Self {
            fib: Vec::new(),
            pit_normal: PitEntry::new(),
            pit_prefix: PitEntry::new(),
            data: None,
            children: Vec::new(),
        }
    }

    fn insert_child<'a>(&mut self, index: usize, component: NameComponent<'a>) {
        let comp = EncodedComponent::from_named_component(component);
        let entry = TableEntry::new();
        self.children.insert(index, (comp, entry));
    }

    fn get_child<'a>(&mut self, component: NameComponent<'a>) -> Option<(&mut TableEntry, usize)> {
        match self
            .children
            .binary_search_by(|x| x.0.compare_to_name_component(component))
        {
            Ok(idx) => Some((&mut self.children[idx].1, idx)),
            Err(_) => None,
        }
    }

    fn get_or_insert_child<'a>(&mut self, component: NameComponent<'a>) -> &mut TableEntry {
        let idx = match self
            .children
            .binary_search_by(|x| x.0.compare_to_name_component(component))
        {
            Ok(idx) => idx,
            Err(idx) => {
                self.insert_child(idx, component);
                idx
            }
        };
        &mut self.children[idx].1
    }

    fn register_prefix<'a, I>(&mut self, remaining_components: &mut I, face: FaceToken, cost: u32)
    where
        I: Iterator<Item = NameComponent<'a>>,
    {
        if let Some(component) = remaining_components.next() {
            // There are more components, so we need to go to children
            self.get_or_insert_child(component)
                .register_prefix(remaining_components, face, cost)
        } else {
            // No more components, can add to this node's FIB
            // Check if already present
            if let Some(index) = self.fib.iter().position(|y| y.next_hop == face) {
                self.fib[index].cost = cost
            } else {
                self.fib.push(FibEntry { cost, next_hop: face });
            }
            self.fib.sort();
        }
    }

    fn unregister_prefix<'a, I>(
        &mut self,
        remaining_components: &mut I,
        face: FaceToken,
        recursive: bool,
        remove_pit: bool,
    ) -> bool
    where
        I: Iterator<Item = NameComponent<'a>>,
    {
        if let Some(component) = remaining_components.next() {
            // There are more components, so we need to check children
            match self.get_child(component) {
                Some(child) => {
                    child
                        .0
                        .unregister_prefix(remaining_components, face, recursive, remove_pit)
                }
                None => return false,
            }
        } else {
            // No more components, can remove from this node's FIB, if present
            let mut any_removed = false;
            if let Some(index) = self.fib.iter().position(|y| y.next_hop == face) {
                self.fib.remove(index);
                any_removed = true
            }
            if remove_pit {
                self.pit_normal.pit_in.retain(|x| x.reply_to != face);
                self.pit_prefix.pit_in.retain(|x| x.reply_to != face);
            }
            if recursive {
                for cc in self.children.iter_mut() {
                    any_removed |=
                        cc.1.unregister_prefix(remaining_components, face, recursive, remove_pit)
                }
            }
            self.children.retain(|c| !c.1.is_empty());
            any_removed
        }
    }

    fn register_interest<'a, I>(
        &mut self,
        name: Name<'a>,
        remaining_components: &mut I,
        can_be_prefix: bool,
        reply_to: FaceToken,
        now: Timestamp,
        deadline: Timestamp,
        nonce: [u8; 4],
        dead_nonce_list: &mut DeadNonceList,
        faces: &mut Vec<(u32, FaceToken)>,
    ) where
        I: Iterator<Item = NameComponent<'a>>,
    {
        if let Some(component) = remaining_components.next() {
            // There are more components, so we need to go to children
            // We ignore the possible duplicates of faces along the way
            //  and add the faces in reverse cost order
            faces.extend(self.fib.iter().rev().map(|x| (x.cost, x.next_hop)));

            let idx = match self
                .children
                .binary_search_by(|x| x.0.compare_to_name_component(component))
            {
                Ok(idx) => idx,
                Err(idx) => {
                    if faces.len() == 0 {
                        // There are no valid faces on this path so we do not even try to create a PIT
                        return;
                    }
                    self.insert_child(idx, component);
                    idx
                }
            };

            self.children[idx].1.register_interest(
                name,
                remaining_components,
                can_be_prefix,
                reply_to,
                now,
                deadline,
                nonce,
                dead_nonce_list,
                faces,
            )
        } else {
            // No more components, will work with this node's PIT
            debug_assert!(faces.len() > 0);

            let relevant_pit = if can_be_prefix {
                &mut self.pit_prefix
            } else {
                &mut self.pit_normal
            };

            // Once we are here, the "faces" contain all the relevant faces in _increased_ priority
            // We need to prune it and leave only the faces to forward on in _ascending_ order

            if relevant_pit.pit_in.len() == 0 {
                // The PIT entry is new, so we always transmit on the highest-priority face
                relevant_pit.pit_in.push(PitInEntry {
                    reply_to,
                    last_nonce: nonce,
                });
                relevant_pit.removal_deadline = deadline;
                relevant_pit.latest_transmission_time = now;
                relevant_pit.transmission_count = 1;
                let reply_to = faces[faces.len() - 1];
                faces.clear();
                faces.push(reply_to);
                return;
            }

            relevant_pit.removal_deadline = relevant_pit.removal_deadline.max(deadline);

            // We next check for nonce loops
            let mut nonce_loop = false;
            let mut reply_to_found = false;
            for ff in relevant_pit.pit_in.iter_mut() {
                if ff.last_nonce == nonce {
                    nonce_loop = true;
                }
                if ff.reply_to == reply_to {
                    if ff.last_nonce != nonce {
                        // Updating the nonce on the entry and storing the old one in dead ones
                        dead_nonce_list.insert(name, nonce, now);
                        ff.last_nonce = nonce;
                    }
                    reply_to_found = true;
                }
            }

            if !reply_to_found {
                // Adding the in entry if it was not there
                relevant_pit.pit_in.push(PitInEntry {
                    reply_to,
                    last_nonce: nonce,
                });
            }

            if nonce_loop {
                // We have a likely loop, so we do not forward
                faces.clear();
                return;
            }

            // We next check if we should suppress this interest
            let minumum_retransamission_delay = MIN_RETRANSMISSION_DELAY_MS
                * (1 << relevant_pit
                    .transmission_count
                    .min(MAX_RETRANSMISSION_DELAY_DOUBLINGS));
            if now
                < relevant_pit
                    .latest_transmission_time
                    .adding(minumum_retransamission_delay)
            {
                // The interest is not forwarded due to retransmission suppression
                faces.clear();
                return;
            }

            // TODO: if we use more complex strategies, e.g. probabilistic ones, we can use the
            //  incoming nonce as the source of randomness (perhaps merging it with local state)

            // We now know that we should forward and pick the latest unused face
            // We pick the face using only the index of the transmission, which assumes
            //  that FIB is stable, but changes to FIB are not critical for correctness.
            relevant_pit.latest_transmission_time = now;
            relevant_pit.transmission_count += 1;
            // We go through all faces one by one _from the end_.
            let face_idx =
                faces.len() - 1 - (relevant_pit.transmission_count as usize % faces.len());
            let reply_to = faces[face_idx];
            faces.clear();
            faces.push(reply_to);
        }
    }

    fn satisfy_interests<'a, I, H>(
        &mut self,
        name: Name<'_>,
        remaining_components: &mut I,
        now: Timestamp,
        dead_nonce_list: &mut DeadNonceList,
        faces: &mut Vec<(u32, FaceToken)>,
        digest_computation: &mut H,
    ) where
        I: Iterator<Item = NameComponent<'a>>,
        H: FnMut() -> [u8; 32],
    {
        // The input name is always "exact", without the digest
        if let Some(component) = remaining_components.next() {
            // This is not the final component, but we can satisfy all of the "can be prefix" PITs
            self.pit_prefix.satisfy(name, now, dead_nonce_list, faces);
            // ... and then descend into children
            let idx = if let Some(child) = self.get_child(component) {
                child.0.satisfy_interests(
                    name,
                    remaining_components,
                    now,
                    dead_nonce_list,
                    faces,
                    digest_computation,
                );
                if child.0.is_empty() {
                    Some(child.1)
                } else {
                    None
                }
            } else {
                None
            };
            // Clean up child if its empty
            if let Some(idx) = idx {
                self.children.remove(idx);
            }
        } else {
            // We have reached the final component, so we can satisfy it from our own PITs
            //  and from children that have the digest
            self.pit_normal.satisfy(name, now, dead_nonce_list, faces);
            self.pit_prefix.satisfy(name, now, dead_nonce_list, faces);

            if self.children.len() > 0 {
                // Try for full name as well
                let digest = digest_computation();
                let component =
                    NameComponent::new(NameComponent::TYPE_IMPLICIT_SHA256, &digest).unwrap();
                let idx = if let Some(child) = self.get_child(component) {
                    child.0.satisfy_interests(
                        name,
                        remaining_components,
                        now,
                        dead_nonce_list,
                        faces,
                        digest_computation,
                    );
                    if child.0.is_empty() {
                        Some(child.1)
                    } else {
                        None
                    }
                } else {
                    None
                };
                // Clean up child if its empty
                if let Some(idx) = idx {
                    self.children.remove(idx);
                }
            }
        }
    }

    fn insert_data<'a, I>(
        &mut self,
        remaining_components: &mut I,
        digest: [u8; 32],
        freshness: u64,
        now: Timestamp,
        data_cache_duration_ms: u64,
        packet: &'a [u8],
    ) where
        I: Iterator<Item = NameComponent<'a>>,
    {
        if let Some(component) = remaining_components.next() {
            // There are more normal components, so we need to go to children
            self.get_or_insert_child(component).insert_data(
                remaining_components,
                digest,
                freshness,
                now,
                data_cache_duration_ms,
                packet,
            );
        } else {
            // We get to the implicit digest component
            let child = self.get_or_insert_child(
                NameComponent::new(NameComponent::TYPE_IMPLICIT_SHA256, digest.as_slice()).unwrap(),
            );
            match child.data.as_mut() {
                Some(entry) => {
                    debug_assert!(packet == entry.data.as_ref());
                    entry.freshness_deadline = entry.freshness_deadline.max(now.adding(freshness));
                }
                None => {
                    child.data = Some(DataEntry {
                        data: Box::from(packet),
                        freshness_deadline: now.adding(freshness),
                        removal_deadline: now.adding(data_cache_duration_ms),
                    })
                }
            }
        }
    }

    fn get_data<'a, I>(
        &mut self,
        remaining_components: &mut I,
        can_be_prefix: bool,
        must_be_fresh: bool,
        now: Timestamp,

        data_cache_duration_ms: u64,
    ) -> Option<&[u8]>
    where
        I: Iterator<Item = NameComponent<'a>>,
    {
        if let Some(component) = remaining_components.next() {
            // There is another component, so we delegate to a child if available
            if let Some(child) = self.get_child(component) {
                return child.0.get_data(
                    remaining_components,
                    can_be_prefix,
                    must_be_fresh,
                    now,
                    data_cache_duration_ms,
                );
            } else {
                return None;
            }
        } else {
            // There are no components, so we need to satisfy from this entry
            if let Some(entry) = self.data.as_mut() {
                if !must_be_fresh || (must_be_fresh && now <= entry.freshness_deadline) {
                    entry.removal_deadline = now.adding(data_cache_duration_ms);
                    return Some(entry.data.as_ref());
                }
            }

            if can_be_prefix {
                // If this can be prefix, we descend into children recursively
                for cc in self.children.iter_mut() {
                    if let Some(data) =
                        cc.1.check_for_data_recursively(must_be_fresh, now, data_cache_duration_ms)
                    {
                        return Some(data);
                    }
                }
            } else {
                // Otherwise, we could also satisfy the interest if the query was without digest
                //  (it is fine to just go to children since if we are already in the digest
                //  entry there will be no children)
                for cc in self.children.iter_mut() {
                    if let Some(entry) = cc.1.data.as_mut() {
                        if !must_be_fresh || (must_be_fresh && now <= entry.freshness_deadline) {
                            entry.removal_deadline = now.adding(data_cache_duration_ms);
                            return Some(entry.data.as_ref());
                        }
                    }
                }
            }
            None
        }
    }

    fn check_for_data_recursively(
        &mut self,
        must_be_fresh: bool,
        now: Timestamp,
        data_cache_duration_ms: u64,
    ) -> Option<&[u8]> {
        if let Some(entry) = self.data.as_mut() {
            if !must_be_fresh || (must_be_fresh && now <= entry.freshness_deadline) {
                entry.removal_deadline = now.adding(data_cache_duration_ms);
                return Some(entry.data.as_ref());
            }
        }

        for cc in self.children.iter_mut() {
            if let Some(data) =
                cc.1.check_for_data_recursively(must_be_fresh, now, data_cache_duration_ms)
            {
                return Some(data);
            }
        }
        None
    }

    fn prune_if_needed(
        &mut self,
        name_so_far: Name<'_>,
        now: Timestamp,
        dead_nonce_list: &mut DeadNonceList,
    ) {
        // First, we ask all chidren to clean up
        for cc in self.children.iter_mut() {
            let component = NameComponent {
                typ: cc.0.typ,
                bytes: &cc.0.bytes,
            };
            let name_so_far = name_so_far.adding_component(component);
            cc.1.prune_if_needed(name_so_far, now, dead_nonce_list);
        }

        // Then we only keep the children that are not empty
        self.children.retain(|cc| !cc.1.is_empty());

        // Then we clean up ourselves
        // Prune stale data
        if let Some(entry) = &self.data {
            if entry.removal_deadline < now {
                self.data = None;
            }
        }

        // Prune stale PIT entries
        if self.pit_normal.removal_deadline < now {
            self.pit_normal.reset(name_so_far, now, dead_nonce_list);
        }
        if self.pit_prefix.removal_deadline < now {
            self.pit_prefix.reset(name_so_far, now, dead_nonce_list);
        }

        // If this entry is empty the parent will clean it up
    }

    fn is_empty(&self) -> bool {
        self.data.is_none()
            && self.fib.len() == 0
            && self.pit_normal.pit_in.len() == 0
            && self.pit_prefix.pit_in.len() == 0
            && self.children.len() == 0
    }

    /*
    fn fib_len(&self) -> usize {
        self.fib.len() + self.children.iter().fold(0, |x, y| x + y.1.fib_len())
    }

    fn pit_len(&self) -> usize {
        self.pit.pit_in.len() + self.children.iter().fold(0, |x, y| x + y.1.pit_len())
    }

    fn cs_len(&self) -> usize {
        let l = if self.data.is_none() { 0 } else { 1 };
        l + self.children.iter().fold(0, |x, y| x + y.1.cs_len())
    }*/
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FibEntry {
    cost: u32,
    next_hop: FaceToken,
}

impl Default for FibEntry {
    fn default() -> Self {
        Self {
            cost: 0,
            next_hop: FaceToken(u32::MAX),
        }
    }
}

struct PitInEntry {
    reply_to: FaceToken,
    last_nonce: [u8; 4],
}

struct PitEntry {
    pit_in: Vec<PitInEntry>,
    removal_deadline: Timestamp,
    latest_transmission_time: Timestamp,
    transmission_count: u8,
}

impl PitEntry {
    fn new() -> Self {
        Self {
            pit_in: Default::default(),
            removal_deadline: Timestamp { ms_since_1970: 0 },
            latest_transmission_time: Timestamp {
                ms_since_1970: u64::MAX,
            },
            transmission_count: 0,
        }
    }

    fn reset(&mut self, name: Name<'_>, now: Timestamp, dead_nonce_list: &mut DeadNonceList) {
        for ee in self.pit_in.drain(..) {
            dead_nonce_list.insert(name, ee.last_nonce, now);
        }
        self.removal_deadline = Timestamp { ms_since_1970: 0 };
        self.latest_transmission_time = Timestamp {
            ms_since_1970: u64::MAX,
        };
        self.transmission_count = 0;
    }

    fn satisfy(
        &mut self,
        name: Name<'_>,
        now: Timestamp,
        dead_nonce_list: &mut DeadNonceList,
        faces: &mut Vec<(u32, FaceToken)>,
    ) {
        for ee in self.pit_in.drain(..) {
            faces.push((0, ee.reply_to));
            dead_nonce_list.insert(name, ee.last_nonce, now);
        }
        self.removal_deadline = Timestamp { ms_since_1970: 0 };
        self.latest_transmission_time = Timestamp {
            ms_since_1970: u64::MAX,
        };
        self.transmission_count = 0;
    }
}

struct DataEntry {
    data: Box<[u8]>,
    freshness_deadline: Timestamp,
    removal_deadline: Timestamp,
}

struct DeadNonceList {
    elements: BTreeMap<u64, Timestamp>,
    duration_to_keep_ms: u64,
}

impl DeadNonceList {
    fn new(duration_to_keep_ms: u64) -> Self {
        Self {
            elements: Default::default(),
            duration_to_keep_ms,
        }
    }

    fn contains(&mut self, name: Name<'_>, nonce: [u8; 4]) -> bool {
        let name_hash = Self::hash_name_and_nonce(name, nonce);
        self.elements.contains_key(&name_hash)
    }

    fn insert(&mut self, name: Name<'_>, nonce: [u8; 4], now: Timestamp) {
        let name_hash = Self::hash_name_and_nonce(name, nonce);
        self.elements
            .insert(name_hash, now.adding(self.duration_to_keep_ms));
    }

    fn prune(&mut self, now: Timestamp) {
        self.elements
            .retain(|_, v| v.ms_since_1970 <= now.ms_since_1970);
    }

    fn hash_name_and_nonce(name: Name<'_>, nonce: [u8; 4]) -> u64 {
        let mut hash = 0u64;
        let mut arr = [0u8; 8];

        for cc in name.components() {
            Self::add_to_hash(&mut hash, cc.typ.get() as u64);
            let mut offset = 0;
            while offset + 8 < cc.bytes.len() {
                arr.copy_from_slice(&cc.bytes[offset..offset + 8]);
                Self::add_to_hash(&mut hash, u64::from_be_bytes(arr) as u64);
                offset += 8;
            }
            if offset < cc.bytes.len() {
                arr.copy_from_slice(&cc.bytes[offset..]);
                Self::add_to_hash(&mut hash, u64::from_be_bytes(arr) as u64);
            }
        }
        Self::add_to_hash(&mut hash, u32::from_be_bytes(nonce) as u64);
        hash
    }

    #[inline]
    fn add_to_hash(hash: &mut u64, i: u64) {
        use core::ops::BitXor;
        *hash = hash
            .rotate_left(5)
            .bitxor(i)
            .wrapping_mul(0x517cc1b727220a95);
    }
}

const DEFAULT_DEADLINE_INCREMENT_MS: u64 = 4000; // 4 sec
                                                 //const RETRANSMISSION_PERIOD_MS: u64 = 1000; // 1 sec

const MIN_RETRANSMISSION_DELAY_MS: u64 = 8;
const MAX_RETRANSMISSION_DELAY_DOUBLINGS: u8 = 5;
