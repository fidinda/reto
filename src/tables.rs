use core::num::{NonZeroU16, NonZeroU32};

use alloc::{collections::BTreeMap, vec::Vec};

use crate::{FaceHandle, Name, NameComponent, NameComponentType, Timestamp};

pub(crate) enum PrefixRegistrationResult {
    NewRegistration,
    PreviousFromSelf,         // Must have a different nonce (or both no nonce)
    PreviousFromOthers(bool), // Should retransmit?
    DeadNonce,
    InvalidName,
}

pub(crate) struct Tables {
    entries: DefaultEntries,
    face_map: BTreeMap<FaceHandle, usize>,
    face_scratch: Vec<(FaceHandle, usize)>,
    pruning_stack: Vec<(EntryIndex, ParentOrSibling)>,
    time_of_last_update: Timestamp,
    events_sice_last_update: u64,
    next_nonce: u32,
}

const NAME_BYTES_PER_ENTRY: usize = 32;
const FIBS_PER_ENTRY: usize = 4;
const PITS_PER_ENTRY: usize = 4;

type DefaultEntries = Entries<NAME_BYTES_PER_ENTRY, FIBS_PER_ENTRY, PITS_PER_ENTRY>;
type DefaultTableEntry = TableEntry<NAME_BYTES_PER_ENTRY, FIBS_PER_ENTRY, PITS_PER_ENTRY>;

impl Tables {
    pub fn new() -> Self {
        let root = TableEntry::default();
        let entries = Entries::new(root);
        Self {
            entries,
            face_map: Default::default(),
            face_scratch: Default::default(),
            pruning_stack: Default::default(),
            time_of_last_update: Timestamp { ms_since_1970: 0 },
            events_sice_last_update: 0,
            next_nonce: 5318,
        }
    }

    // Common methods
    pub fn next_nonce(&mut self) -> [u8; 4] {
        // djb2 hash using a function of the current table state as key
        let key = (self.entries.entries.len() + 1) as u32 * 7 + self.events_sice_last_update as u32;
        self.next_nonce = (self.next_nonce * 33) ^ key;
        self.next_nonce.to_be_bytes()
    }

    pub fn unregister_face<'a>(&mut self, face: FaceHandle) {
        for entry in self.entries.entries.iter_mut() {
            if entry.is_unused {
                continue;
            }
            for i in (0..entry.fibs_len as usize).rev() {
                if entry.fibs[i].next_hop == face {
                    // Remove the PIT entry
                    entry.fibs[i] = entry.fibs[entry.fibs_len as usize - 1];
                    entry.fibs_len -= 1;
                }
            }
            for i in (0..entry.pit.pits_len as usize).rev() {
                if entry.pit.reply_to[i] == face {
                    // Remove the PIT entry
                    entry.pit.reply_to[i] = entry.pit.reply_to[entry.pit.pits_len as usize - 1];
                    entry.pit.can_be_prefix[i] =
                        entry.pit.can_be_prefix[entry.pit.pits_len as usize - 1];
                    entry.pit.pits_len -= 1;
                }
            }
        }
        self.prune_stale_entries(None)
    }

    // FIB methods
    pub fn register_prefix<'a>(&mut self, name_prefix: Name<'a>, face: FaceHandle) {
        let fib_entry = FibEntry { next_hop: face };

        let (mut entry, insertion_index) = if name_prefix.component_count() == 0 {
            let insertion_index = self.entries.next_insertion_index();
            (self.entries.root_mut(), insertion_index)
        } else {
            let (entry_index, _) = self
                .entries
                .get_or_create_nonroot_entry_index_for_name(name_prefix);
            let insertion_index = self.entries.next_insertion_index();
            (self.entries.entry_mut(&entry_index), insertion_index)
        };

        loop {
            // TODO: this might add multiple FIBs for the same face (if they are in continuations)
            // Check if entry is already present
            if entry.fibs[..(entry.fibs_len as usize)].contains(&fib_entry) {
                return;
            }

            if entry.fibs_len + 1 < FIBS_PER_ENTRY as u8 {
                // If we can add a new FIB entry, just add
                entry.fibs[entry.fibs_len as usize] = FibEntry { next_hop: face };
                entry.fibs_len += 1;
                return;
            } else if entry.is_continued {
                // We cannot add and there are further entries that extend this
                //  so we repeat the procedure
                let next_entry = entry.next_sibling.unwrap();
                entry = self.entries.entry_mut(&next_entry);
                continue;
            } else {
                // There are no slots and no continuation, so we must create one
                let mut new_entry = DefaultTableEntry::default();
                new_entry.fibs[0] = fib_entry;
                entry.fibs_len = 1;
                new_entry.is_continued = false;
                new_entry.next_sibling = entry.next_sibling;

                entry.is_continued = true;
                entry.next_sibling = Some(insertion_index);

                self.entries.insert(new_entry, insertion_index);
                return;
            }
        }
    }

    pub fn unregister_prefix<'a>(&mut self, name_prefix: Name<'a>, face: FaceHandle) -> bool {
        let fib_entry = FibEntry { next_hop: face };

        let mut entry = if name_prefix.component_count() == 0 {
            self.entries.root_mut()
        } else {
            if let Some(entity_index) = self.entries.get_nonroot_entry_index_for_name(name_prefix) {
                self.entries.entry_mut(&entity_index)
            } else {
                return false;
            }
        };

        loop {
            for i in 0..entry.fibs_len as usize {
                // If found we replace it with the last entry and decrement count
                if entry.fibs[i] == fib_entry {
                    entry.fibs[i] = entry.fibs[entry.fibs_len as usize - 1];
                    entry.fibs_len -= 1;
                    return true;
                }
            }
            if entry.is_continued {
                // It might be in the continuation
                let next_entry = entry.next_sibling.unwrap();
                entry = self.entries.entry_mut(&next_entry);
            } else {
                return false;
            }
        }
    }

    pub fn hops_for_name<'a>(&mut self, name: Name<'a>) -> impl Iterator<Item = FaceHandle> + '_ {
        // We want to return the unique set of faces ordered by depth
        self.face_map.clear();
        self.face_scratch.clear();
        for (entry_index, depth) in self.entries.entries_mut_for_prefixes_of_name(name) {
            if let Some(entry_index) = entry_index {
                let entry = self.entries.entry(&entry_index);
                for i in 0..entry.fibs_len as usize {
                    self.face_map
                        .entry(entry.fibs[i].next_hop)
                        .and_modify(|curr| *curr = depth.max(*curr))
                        .or_insert(depth);
                }
            }
        }
        self.face_scratch = self.face_map.iter().map(|(a, b)| (*a, *b)).collect();
        self.face_scratch.sort_by(|a, b| b.1.cmp(&a.1));
        self.face_scratch.iter().map(|(f, _)| *f)
    }

    // PIT methods
    // Returns whether the PIT has already covered this name
    //  if it was received from a _different_ face
    pub fn register_interest<'a>(
        &mut self,
        name: Name<'a>,
        can_be_prefix: bool,
        reply_to: FaceHandle,
        now: Timestamp,
        retransmission_period: u64,
        deadline: Timestamp,
        nonce: Option<[u8; 4]>,
    ) -> PrefixRegistrationResult {
        if name.component_count() == 0 {
            return PrefixRegistrationResult::InvalidName;
        }

        self.events_sice_last_update += 1;

        let (entry_index, is_new) = self
            .entries
            .get_or_create_nonroot_entry_index_for_name(name);

        let insertion_index = self.entries.next_insertion_index();

        let entry = self.entries.entry_mut(&entry_index);

        if is_new || (!entry.is_continued && entry.pit.pits_len == 0) {
            // This is a new entry (or an entry with no pit info), so things are easy
            entry.pit.reply_to[0] = reply_to;
            entry.pit.can_be_prefix[0] = can_be_prefix;
            entry.pit.pits_len = 1;

            if let Some(nonce) = nonce {
                entry.pit.nonces[0] = nonce;
                entry.pit.nonces_len = 1;
            }

            entry.pit.deadline = deadline;
            entry.pit.next_transmission =
                now.max(entry.pit.next_transmission.adding(retransmission_period));

            return PrefixRegistrationResult::NewRegistration;
        }

        // We now know it is not the first time we receive the interest.
        // If we have previously seen nonces for this name same as the one we got
        //  we reject the packet as it is likely in a loop.
        if let Some(nonce) = nonce {
            let mut entry = self.entries.entry(&entry_index);
            loop {
                if entry.pit.nonces[..entry.pit.nonces_len as usize].contains(&nonce) {
                    return PrefixRegistrationResult::DeadNonce;
                }
                if entry.is_continued {
                    entry = self.entries.entry(&entry.next_sibling.unwrap())
                } else {
                    break;
                }
            }

            // Save the nonce if there is space (but we don't create new things just for nonces)
            let mut entry = self.entries.entry_mut(&entry_index);
            loop {
                if (entry.pit.nonces_len as usize) < entry.pit.nonces.len() {
                    entry.pit.nonces[entry.pit.nonces_len as usize] = nonce;
                    entry.pit.nonces_len += 1;
                    break;
                } else if entry.is_continued {
                    let index = entry.next_sibling.unwrap();
                    entry = self.entries.entry_mut(&index);
                } else {
                    // We replace the earliest nonce (not bothering about the previous entries if any)
                    for i in 0..(entry.pit.nonces_len as usize - 1) {
                        entry.pit.nonces[i] = entry.pit.nonces[i + 1];
                    }
                    entry.pit.nonces[entry.pit.nonces_len as usize - 1] = nonce;
                    break;
                }
            }
        }

        let mut others_have_asked = false;

        let mut entry = self.entries.entry_mut(&entry_index);
        let should_retransmit = entry.pit.next_transmission <= now;
        entry.pit.next_transmission =
            now.max(entry.pit.next_transmission.adding(retransmission_period));
        entry.pit.deadline = entry.pit.deadline.max(deadline);

        loop {
            for (idx, face) in entry.pit.reply_to[..entry.pit.pits_len as usize]
                .iter()
                .enumerate()
            {
                if face == &reply_to {
                    entry.pit.can_be_prefix[idx] |= can_be_prefix;
                    return PrefixRegistrationResult::PreviousFromSelf;
                } else {
                    others_have_asked = true;
                }
            }
            if entry.is_continued {
                let index = entry.next_sibling.unwrap();
                entry = self.entries.entry_mut(&index);
            } else {
                break;
            }
        }

        // Now we know that we did not ask for this before, so we need to add a new PIT record
        // We also know we are not already part of the PIT
        loop {
            if entry.pit.pits_len + 1 < PITS_PER_ENTRY as u8 {
                // If we can add a new PIT entry, just add
                entry.pit.reply_to[entry.fibs_len as usize] = reply_to;
                entry.pit.can_be_prefix[entry.fibs_len as usize] = can_be_prefix;
                entry.pit.pits_len += 1;
                break;
            } else if entry.is_continued {
                // We cannot add and there are further entries that extend this
                //  so we repeat the procedure
                let next_entry = entry.next_sibling.unwrap();
                entry = self.entries.entry_mut(&next_entry);
                continue;
            } else {
                // There are no slots and no continuation, so we must create one
                let mut pit_entry = PitEntry::default();
                pit_entry.reply_to[0] = reply_to;
                pit_entry.can_be_prefix[0] = can_be_prefix;
                pit_entry.pits_len = 1;

                if let Some(nonce) = nonce {
                    pit_entry.nonces[0] = nonce;
                    pit_entry.nonces_len = 1;
                }

                pit_entry.deadline = deadline;
                pit_entry.next_transmission = now.adding(retransmission_period);

                let mut new_entry = DefaultTableEntry::default();
                new_entry.pit = pit_entry;
                new_entry.is_continued = false;
                new_entry.next_sibling = entry.next_sibling;

                entry.is_continued = true;
                entry.next_sibling = Some(insertion_index);

                self.entries.insert(new_entry, insertion_index);
                break;
            }
        }

        if others_have_asked {
            PrefixRegistrationResult::PreviousFromOthers(should_retransmit)
        } else {
            PrefixRegistrationResult::NewRegistration
        }
    }

    pub fn satisfy_interests<'a>(
        &mut self,
        name: Name<'a>,
        digest: [u8; 32],
        now: Timestamp,
    ) -> impl Iterator<Item = FaceHandle> + '_ {
        self.events_sice_last_update += 1;

        self.face_map.clear();
        self.face_scratch.clear();

        // TODO: check for off-by-ones
        let max_depth_without_digest = name.component_count();

        let digest_component = NameComponent::new(NameComponentType::ImplicitSha256Digest, &digest);
        let full_name = name.adding_component(digest_component);

        // TODO: fix allocations
        let vec: Vec<_> = self
            .entries
            .entries_mut_for_prefixes_of_name(full_name)
            .collect();

        for (entry_index, depth) in vec {
            let entry = match entry_index {
                Some(entry_index) => self.entries.entry_mut(&entry_index),
                None => self.entries.root_mut(),
            };
            let is_full_name = depth >= max_depth_without_digest;

            // Iterate in reverse for easy switch removal
            for i in (0..entry.pit.pits_len as usize).rev() {
                if entry.pit.can_be_prefix[i] || is_full_name {
                    // Should return face...
                    self.face_map
                        .entry(entry.pit.reply_to[i])
                        .and_modify(|curr| *curr = depth.max(*curr))
                        .or_insert(depth);
                    // ...and remove it
                    entry.pit.reply_to[i] = entry.pit.reply_to[entry.pit.pits_len as usize - 1];
                    entry.pit.can_be_prefix[i] =
                        entry.pit.can_be_prefix[entry.pit.pits_len as usize - 1];
                    entry.pit.pits_len -= 1;
                }
            }
        }

        if self.events_sice_last_update >= EVENTS_BEFORE_PRUNE
            || now
                .difference(&self.time_of_last_update)
                .unwrap_or(MS_BEFORE_PRUNE)
                >= MS_BEFORE_PRUNE
        {
            self.events_sice_last_update = 0;
            self.time_of_last_update = now;
            self.prune_stale_entries(Some(now.removing(PRUNING_SLACK_MS)))
        }

        self.face_scratch = self.face_map.iter().map(|(a, b)| (*a, *b)).collect();
        self.face_scratch.sort_by(|a, b| b.1.cmp(&a.1));
        self.face_scratch.iter().map(|(f, _)| *f)
    }

    fn prune_stale_entries<'a>(&mut self, deadline: Option<Timestamp>) {
        // First, we compact the root (ignoring the deadline because no PITs)
        let (first_child, _, _) = Self::compact_entry_chain(None, &mut self.entries, None, None);

        let mut current_node = match first_child {
            Some(first_child) => first_child,
            None => return,
        };

        let mut current_target = ParentOrSibling::Parent(None);

        self.pruning_stack.clear();

        // We go depth first and want to preserve all "next_siblings" on each level we visit
        //  so we can revisit them later. Keep an explicit index stack, so no recursion.
        loop {
            let (first_child, next_sibling, next_target) = Self::compact_entry_chain(
                Some(current_node),
                &mut self.entries,
                deadline,
                Some(current_target),
            );

            if let Some(first_child) = first_child {
                // There is a child, so we preserve the sibling (if present) and go into child
                if let (Some(next_sibling), Some(next_target)) = (next_sibling, next_target) {
                    self.pruning_stack.push((next_sibling, next_target));
                }
                current_target = ParentOrSibling::Parent(Some(current_node));
                current_node = first_child;
            } else if let Some(next_sibling) = next_sibling {
                // No child, so we just process this one
                current_target = ParentOrSibling::Sibling(current_node);
                current_node = next_sibling;
            } else {
                // We have reached the end of the branch, so now we want to pop the previous level
                if let Some((node, target)) = self.pruning_stack.pop() {
                    current_target = target;
                    current_node = node;
                }
            }
        }
    }

    // Returns fist_child and the last next_sibling
    fn compact_entry_chain(
        initial: Option<EntryIndex>,
        entries: &mut DefaultEntries,
        deadline: Option<Timestamp>,
        target: Option<ParentOrSibling>,
    ) -> (
        Option<EntryIndex>,
        Option<EntryIndex>,
        Option<ParentOrSibling>,
    ) {
        // First we want to purge all the stale PIT entries
        //  and collect the overall statistics on the chain
        let mut fib_count: usize = 0;
        let mut pit_count: usize = 0;
        let mut first_child = None;

        let mut entry = match initial {
            Some(idx) => entries.entry_mut(&idx),
            None => entries.root_mut(),
        };

        loop {
            if let Some(deadline) = deadline {
                if entry.pit.deadline < deadline {
                    // Reset the PIT entry faces (but keep the nonces just in case)
                    entry.pit.pits_len = 0;
                }
            }
            fib_count += entry.fibs_len as usize;
            pit_count += entry.pit.pits_len as usize;
            if first_child.is_none() {
                first_child = entry.first_child
            };

            if entry.is_continued {
                let idx = entry.next_sibling.unwrap();
                entry = entries.entry_mut(&idx)
            } else {
                break;
            }
        }

        let next_sibling = entry.next_sibling;
        let next_target;

        if (fib_count + pit_count == 0) && first_child.is_none() {
            // The whole chain is useless, so we can pop off the whole thing

            // First we patch the target with the next_sibling value of the
            //  last entity in the chain, which we conveniently have.
            match target {
                Some(ParentOrSibling::Parent(None)) => {
                    entries.root_mut().first_child = next_sibling
                }
                Some(ParentOrSibling::Parent(Some(e))) => {
                    entries.entry_mut(&e).first_child = next_sibling
                }
                Some(ParentOrSibling::Sibling(e)) => {
                    entries.entry_mut(&e).next_sibling = next_sibling
                }
                None => {} // the chain starts with root, nothing to update
            }

            // And then we remove every entry in the chain
            let mut next_sibling = match initial {
                Some(idx) => entries.remove(idx).next_sibling,
                None => entries.root().next_sibling,
            };

            while let Some(idx) = next_sibling {
                next_sibling = entries.remove(idx).next_sibling;
            }

            next_target = target;
        } else {
            next_target = Some(ParentOrSibling::Sibling(initial.unwrap()))
        }

        // Can introduce more efficient approaches here, e.g. moving things
        //  from continuations to previous ones and then dropping empty continuations.

        (first_child, next_sibling, next_target)
    }
}

const EVENTS_BEFORE_PRUNE: u64 = 100;
const MS_BEFORE_PRUNE: u64 = 100;

// If the deadline is a bit ahead of now we can keep the satisfied interests
//  for a little longer to serve as something like a Dead Nonce List.
// Basically want to ensure that if the interest loops the PIT is kept for longer
//  so the nonces are still present even if it cannot satisfy a data anymore
//  since the reply_tos have been removed.

const PRUNING_SLACK_MS: u64 = 1000;

#[derive(Clone, Copy)]
struct EntryIndex {
    idx: NonZeroU32,
}

struct Entries<const N: usize, const F: usize, const P: usize> {
    entries: Vec<TableEntry<N, F, P>>,
}

impl<const N: usize, const F: usize, const P: usize> Entries<N, F, P> {
    fn new(first_one: TableEntry<N, F, P>) -> Self {
        Self {
            entries: alloc::vec![first_one],
        } // will never be deleted
    }

    fn root(&self) -> &TableEntry<N, F, P> {
        &self.entries[0]
    }

    fn root_mut(&mut self) -> &mut TableEntry<N, F, P> {
        &mut self.entries[0]
    }

    fn entry(&self, index: &EntryIndex) -> &TableEntry<N, F, P> {
        &self.entries[index.idx.get() as usize]
    }

    fn entry_mut(&mut self, index: &EntryIndex) -> &mut TableEntry<N, F, P> {
        &mut self.entries[index.idx.get() as usize]
    }

    fn next_insertion_index(&self) -> EntryIndex {
        for (idx, ee) in self.entries.iter().enumerate() {
            if ee.is_unused {
                return EntryIndex {
                    idx: (idx as u32).try_into().unwrap(),
                };
            }
        }
        let idx = self.entries.len();
        EntryIndex {
            idx: (idx as u32).try_into().unwrap(),
        }
    }

    fn insert(&mut self, entry: TableEntry<N, F, P>, index: EntryIndex) {
        if index.idx.get() as usize == self.entries.len() {
            self.entries.push(entry);
        } else {
            self.entries[index.idx.get() as usize] = entry;
        }
    }

    fn remove(&mut self, index: EntryIndex) -> &TableEntry<N, F, P> {
        self.entries[index.idx.get() as usize].is_unused = true;
        &self.entries[index.idx.get() as usize]
    }

    fn get_nonroot_entry_index_for_name<'a>(&self, name: Name<'a>) -> Option<EntryIndex> {
        let mut current_node = self.root().first_child;
        'comp: for component in name.components() {
            let mut remaining_name = component.bytes;
            let mut is_in_unmatched_chain = false;
            while let Some(cc) = current_node {
                let entry = self.entry(&cc);
                let len = remaining_name.len().min(entry.name_len as usize);

                if !is_in_unmatched_chain
                    && entry.name_type == component.typ
                    && entry.name() == &remaining_name[..len]
                {
                    if entry.is_continued {
                        current_node = entry.next_sibling;
                        remaining_name = &remaining_name[len..];
                    } else {
                        current_node = entry.first_child;
                        continue 'comp;
                    }
                } else {
                    current_node = entry.next_sibling;
                    if entry.is_continued {
                        is_in_unmatched_chain = true;
                    } else {
                        is_in_unmatched_chain = false;
                        remaining_name = component.bytes;
                    }
                }
            }
            break;
        }
        None
    }

    fn get_or_create_nonroot_entry_index_for_name<'a>(
        &mut self,
        name: Name<'a>,
    ) -> (EntryIndex, bool) {
        let mut is_new = false;
        let mut current_node = self.root().first_child;

        let mut target = ParentOrSibling::Parent(None);

        'comp: for component in name.components() {
            let name_type = component.typ;
            let mut remaining_name = component.bytes;
            let mut is_in_unmatched_chain = false;

            while let Some(cc) = current_node {
                let entry = self.entry(&cc);
                let len = remaining_name.len().min(entry.name_len as usize);

                if !is_in_unmatched_chain
                    && entry.name_type == name_type
                    && entry.name() == &remaining_name[..len]
                {
                    if entry.is_continued {
                        target = ParentOrSibling::Sibling(cc);
                        current_node = entry.next_sibling;
                        remaining_name = &remaining_name[len..];
                    } else {
                        target = ParentOrSibling::Parent(Some(cc));
                        current_node = entry.first_child;
                        continue 'comp;
                    }
                } else {
                    current_node = entry.next_sibling;
                    target = ParentOrSibling::Sibling(cc);
                    if entry.is_continued {
                        is_in_unmatched_chain = true;
                    } else {
                        is_in_unmatched_chain = false;
                        remaining_name = component.bytes;
                    }
                }
            }

            // There is no proper component, so we add it
            is_new = true;
            let mut remaining_name = component.bytes;
            loop {
                let (entry, rem) = TableEntry::new(name_type, remaining_name);
                let index = self.next_insertion_index();
                self.insert(entry, index);

                match target {
                    ParentOrSibling::Parent(None) => self.root_mut().first_child = Some(index),
                    ParentOrSibling::Parent(Some(e)) => {
                        self.entry_mut(&e).first_child = Some(index)
                    }
                    ParentOrSibling::Sibling(e) => self.entry_mut(&e).next_sibling = Some(index),
                }

                target = ParentOrSibling::Sibling(index);

                if let Some(rem) = rem {
                    remaining_name = rem;
                } else {
                    target = ParentOrSibling::Parent(Some(index));
                    break;
                }
            }
        }

        match target {
            ParentOrSibling::Parent(Some(index)) => (index, is_new),
            // We cannot have an empty name here, so not a root,
            //  and the 'outer loop must always end with the Parent target
            _ => unreachable!(),
        }
    }

    fn entries_mut_for_prefixes_of_name<'a>(
        &'a self,
        name: Name<'a>,
    ) -> impl Iterator<Item = (Option<EntryIndex>, usize)> + 'a {
        EntryIterator {
            name_component_iter: name.components(),
            entries: self,
            entry_index: None,
            depth: 0,
        }
    }
}

struct EntryIterator<
    'a,
    I: Iterator<Item = NameComponent<'a>>,
    const N: usize,
    const F: usize,
    const P: usize,
> {
    name_component_iter: I,
    entries: &'a Entries<N, F, P>,
    entry_index: Option<EntryIndex>,
    depth: usize,
}

impl<'a, I: Iterator<Item = NameComponent<'a>>, const N: usize, const F: usize, const P: usize>
    Iterator for EntryIterator<'a, I, N, F, P>
{
    type Item = (Option<EntryIndex>, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.depth == 0 {
            let entry = self.entries.root();
            self.entry_index = entry.first_child;
            return Some((None, self.depth));
        }

        self.depth += 1;

        let component = self.name_component_iter.next()?;
        debug_assert!(component.bytes.len() <= N); // Not handling long names for now

        loop {
            let returned_index = self.entry_index?;
            let entry = self.entries.entry(&returned_index);
            if entry.name_type == component.typ && entry.name() == component.bytes {
                self.entry_index = entry.first_child;
                return Some((Some(returned_index), self.depth));
            } else {
                self.entry_index = entry.next_sibling;
            }
        }
    }
}

struct TableEntry<const N: usize, const F: usize, const P: usize> {
    name: [u8; N],
    fibs: [FibEntry; F],
    pit: PitEntry<P>,

    name_type: NonZeroU16,
    name_len: u8,
    fibs_len: u8,

    is_continued: bool, // next sibling is actually the continuation of this one
    is_unused: bool,    // in place of the option

    next_sibling: Option<EntryIndex>,
    first_child: Option<EntryIndex>,
}

impl<const N: usize, const F: usize, const P: usize> TableEntry<N, F, P> {
    // Creates a default empty node and returns the part of the name that did not fit, if any
    // The "next sibling" will need to be set
    fn new(name_type: NonZeroU16, name_bytes: &[u8]) -> (Self, Option<&[u8]>) {
        let name_len = name_bytes.len().min(N);
        let is_continued = name_bytes.len() > N;
        let mut ret = Self {
            name: [0; N],
            fibs: [FibEntry::default(); F],
            pit: PitEntry::default(),
            name_type,
            name_len: name_len as u8,
            fibs_len: 0,
            is_continued,
            is_unused: false,
            next_sibling: None,
            first_child: None,
        };

        ret.name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        let remaining = if is_continued {
            Some(&name_bytes[name_len..])
        } else {
            None
        };
        (ret, remaining)
    }

    fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

impl<const N: usize, const F: usize, const P: usize> Default for TableEntry<N, F, P> {
    fn default() -> Self {
        Self::new(8.try_into().unwrap(), &[]).0
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FibEntry {
    next_hop: FaceHandle,
}

impl Default for FibEntry {
    fn default() -> Self {
        Self {
            next_hop: FaceHandle(u32::MAX),
        }
    }
}

#[derive(Copy, Clone)]
struct PitEntry<const P: usize> {
    deadline: Timestamp,
    next_transmission: Timestamp,
    reply_to: [FaceHandle; P],

    // TODO: bits
    can_be_prefix: [bool; P],

    nonces: [[u8; 4]; 2],
    nonces_len: u8,
    pits_len: u8,
}

impl<const P: usize> Default for PitEntry<P> {
    fn default() -> Self {
        Self {
            can_be_prefix: [false; P],
            reply_to: [FaceHandle(u32::MAX); P],
            deadline: Timestamp {
                ms_since_1970: u64::MIN,
            },
            nonces: Default::default(),
            nonces_len: 0,
            next_transmission: Timestamp {
                ms_since_1970: u64::MAX,
            },
            pits_len: 0,
        }
    }
}

#[derive(Copy, Clone)]
enum ParentOrSibling {
    Parent(Option<EntryIndex>), // None if root
    Sibling(EntryIndex),
}
