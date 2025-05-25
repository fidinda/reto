use core::marker::PhantomData;
use core::num::NonZeroU32;

use alloc::{boxed::Box, vec::Vec};

use crate::tables::{PrefixRegistrationResult, Tables};

use crate::{
    Clock, ContentStore, Data, Digest, FaceError, FaceReceiver, FaceSender, Hasher, Interest, Name,
    Sha256Digest,
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaceToken(pub(crate) u32);

enum ForwarderError<'a> {
    FacesDisconnected(&'a [FaceToken]),
}

struct Forwarder<CS, C, H>
where
    CS: ContentStore,
    C: Clock,
    H: Hasher<32, Digest = Sha256Digest>,
{
    faces: Faces,
    tables: Tables,
    content_store: CS,
    clock: C,
    last_checked_face: usize,
    disconnected_faces: Vec<FaceToken>,
    _hash: PhantomData<H>,
}

impl<CS, C, H> Forwarder<CS, C, H>
where
    CS: ContentStore,
    C: Clock,
    H: Hasher<32, Digest = Sha256Digest>,
{
    pub fn new(content_store: CS, clock: C) -> Self {
        let faces = Faces::new();
        let tables = Tables::new();

        Self {
            faces,
            tables,
            content_store,
            clock,
            last_checked_face: 0,
            disconnected_faces: Default::default(),
            _hash: PhantomData,
        }
    }

    pub fn add_face<FS, FR>(&mut self, sender: FS, receiver: FR) -> Option<FaceToken>
    where
        FS: FaceSender + 'static,
        FR: FaceReceiver + 'static,
    {
        self.faces.add_face(sender, receiver)
    }

    pub fn remove_face(&mut self, token: FaceToken) -> bool {
        self.faces.remove_face(token)
    }

    pub fn register_name_prefix_for_forwarding<'a>(
        &mut self,
        name_prefix: Name<'a>,
        forward_to: FaceToken,
    ) {
        self.tables.register_prefix(name_prefix, forward_to)
    }

    pub fn unregister_name_prefix_for_forwarding<'a>(
        &mut self,
        name_prefix: Name<'a>,
        forward_to: FaceToken,
    ) -> bool {
        self.tables.unregister_prefix(name_prefix, forward_to)
    }

    pub fn try_recv(&mut self, face: Option<&FaceToken>) -> Result<bool, ForwarderError> {
        self.disconnected_faces.clear();

        let mut any_received = false;

        if let Some(token) = face {
            // If we were given an explicit face to try we try it
            if let Some(index) = Faces::find_face(&self.faces.faces, token) {
                any_received |= self.try_recv_from_face(index)
            }
        } else {
            // Otherwise we try all the faces in turn
            for _ in 0..self.faces.len() {
                self.last_checked_face = if self.last_checked_face >= self.faces.len() {
                    0
                } else {
                    self.last_checked_face + 1
                };
                any_received |= self.try_recv_from_face(self.last_checked_face)
            }
        }

        if self.disconnected_faces.len() > 0 {
            Err(ForwarderError::FacesDisconnected(&self.disconnected_faces))
        } else {
            Ok(any_received)
        }
    }

    fn try_recv_from_face(&mut self, index: usize) -> bool {
        let (recv_buffer, recv_buffer_cursor) = &mut self.faces.recv_buffers[index];

        let mut any_received = false;

        let origin = {
            let (token, entry) = &mut self.faces.faces[index];
            match entry.try_recv(recv_buffer, recv_buffer_cursor) {
                Ok(bytes_received) => {
                    if bytes_received == 0 {
                        return false; // Nothing was received, the face is not ready
                    }
                }
                Err(FaceError::Disconnected) => self.disconnected_faces.push(FaceToken(*token)),
            }
            FaceToken(*token)
        };

        // We know know that we have got some new bytes, so we will try to parse the packets
        loop {
            let mut cursor = 0usize;
            let typ = unsafe { NonZeroU32::new_unchecked(5) }; // peek int
            cursor += 3;

            let len = 12usize; // peek len
            cursor += 3;

            if cursor + len > *recv_buffer_cursor {
                break; // The packet is incomplete, so we return
            }

            // If we are here, we could process the full packet
            let (original_packet, rest) = recv_buffer.split_at_mut(cursor + len);

            match typ.get() {
                TLV_TYPE_INTEREST => {
                    // Handle interest
                    if let Some(interest) =
                        Interest::from_bytes(&original_packet[cursor..(cursor + len)])
                    {
                        Self::handle_interest(
                            interest,
                            original_packet,
                            origin,
                            &mut self.tables,
                            &mut self.content_store,
                            &mut self.clock,
                            &mut self.faces.faces,
                            &mut self.disconnected_faces,
                        );
                        any_received = true;
                    } // Otherwise ignore the malformed packet
                }
                TLV_TYPE_DATA => {
                    // Handle data
                    if let Some(data) = Data::from_bytes(&original_packet[cursor..(cursor + len)]) {
                        Self::handle_data(
                            data,
                            original_packet,
                            origin,
                            &mut self.tables,
                            &mut self.content_store,
                            &mut self.clock,
                            &mut self.faces.faces,
                            &mut self.disconnected_faces,
                        );
                        any_received = true;
                    } // Otherwise ignore the malformed packet
                }
                _ => {} // Otherwise we ignore the packet
            }

            if cursor + len < *recv_buffer_cursor {
                // There are still some unprocessed bytes, so we want to loop again
                recv_buffer.copy_within((cursor + len)..*recv_buffer_cursor, 0);
                *recv_buffer_cursor -= cursor + len;
            } else {
                // We are done with this bunch of bytes
                *recv_buffer_cursor = 0;
                break;
            }
        }

        any_received
    }

    fn handle_interest<'a>(
        interest: Interest<'a>,
        original_packet: &'a mut [u8],
        origin: FaceToken,
        tables: &mut Tables,
        content_store: &mut CS,
        clock: &mut C,
        faces: &mut [(u32, FaceEntry)],
        disconnected_faces: &mut Vec<FaceToken>,
    ) {
        // Interest must have a non-empty name
        if interest.name.component_count() == 0 {
            return;
        };

        // We want to drop packets if they have hop limit of 0,
        //  otherwise we want to decrement it. If the resulting
        //  hop limit is 0 we will only try to satisfy this from
        //  the content store, but not forward.
        // If no hop limit is present we always accept the interest.
        let (is_last_hop, hop_needs_decrement) = match &interest.hop_limit {
            Some(hop) => {
                if *hop == 0 {
                    return;
                } else {
                    (*hop == 1, true)
                }
            }
            None => (false, false),
        };

        // We check the PIT before CS because it is smaller/faster
        //  and if the interest is already there then we know we
        //  could not have satisfied it from CS.

        let now = clock.now();

        if !is_last_hop {
            let deadline = match interest.interest_lifetime {
                Some(ms) => now.adding(ms),
                None => now.adding(DEFAULT_DEADLINE_INCREMENT_MS),
            };

            match tables.register_interest(
                interest.name,
                interest.can_be_prefix,
                origin,
                now,
                RETRANSMISSION_PERIOD_MS,
                deadline,
                interest.nonce,
            ) {
                PrefixRegistrationResult::NewRegistration => {
                    // This is the first time (in recent past) that we see this packet, forward through
                }
                PrefixRegistrationResult::PreviousFromSelf => {
                    // We treat this as a retransmission and always send the packet forward
                }
                PrefixRegistrationResult::PreviousFromOthers(should_retransmit) => {
                    // The PIT already has others applying, so we only forward if it was not too long ago
                    if !should_retransmit {
                        return;
                    }
                }
                PrefixRegistrationResult::DeadNonce => {
                    // The interest likely looped, so we drop it
                    return;
                }
                PrefixRegistrationResult::InvalidName => {
                    // The interest has an invalid name, so we drop it
                    return;
                }
            }
        }

        // Then we try to satisfy the interest from our local cache
        let freshness_requirement = if interest.must_be_fresh {
            Some(now)
        } else {
            None
        };

        if let Ok(Some(retrieved)) =
            content_store.get(interest.name, interest.can_be_prefix, freshness_requirement)
        {
            // The packet is found so we simply reply to the same face
            if let Some(index) = Faces::find_face(&faces, &origin) {
                if let Err(FaceError::Disconnected) = faces[index].1.send(retrieved) {
                    disconnected_faces.push(origin);
                }
            }
            return;
        }

        // Finally, if this is not the last hop of the interest we try to forward it.
        if !is_last_hop {
            // If the interest is missing a nonce we should add one before forwarding
            // But do not for now, since it requires re-encoding the interest
            /*if interest.nonce.is_none() {
                let nonce = inner.tables.next_nonce();
                interest.nonce = Some(nonce);
                interest_modified = true;
            }*/

            if hop_needs_decrement {
                if let Some(hop_byte_index) = interest.index_of_hop_byte() {
                    original_packet[hop_byte_index] =
                        original_packet[hop_byte_index].saturating_sub(1);
                }
            }

            // We now know we need to forward the interest, just need to check where to send it
            // The strategy we use is basically multicast to all relevant faces, nothing complex.
            for next_hop in tables.hops_for_name(interest.name) {
                // Never forward back to the same face
                if next_hop != origin {
                    if let Some(index) = Faces::find_face(&faces, &next_hop) {
                        if let Err(FaceError::Disconnected) = faces[index].1.send(&original_packet)
                        {
                            disconnected_faces.push(next_hop);
                        }
                    }
                }
            }
        }
    }

    fn handle_data<'a>(
        data: Data<'a>,
        original_packet: &'a [u8],
        origin: FaceToken,
        tables: &mut Tables,
        content_store: &mut CS,
        clock: &mut C,
        faces: &mut [(u32, FaceEntry)],
        disconnected_faces: &mut Vec<FaceToken>,
    ) {
        let mut is_unsolicited: bool = true;

        let now = clock.now();

        let mut hasher = H::new();
        // TODO: test this!!! Probably inside the tlv, not packet?
        hasher.update(
            &original_packet[data.signed_range_in_parent_tlv.0..data.signed_range_in_parent_tlv.1],
        );
        let digest = hasher.finalize().into_inner();

        // First we try to find the interest in the PIT and send it to every
        //  requesting face other than the face we got it from.
        for face in tables.satisfy_interests(data.name, digest, now) {
            is_unsolicited = false;
            if face != origin {
                if let Some(index) = Faces::find_face(&faces, &face) {
                    if let Err(FaceError::Disconnected) = faces[index].1.send(original_packet) {
                        disconnected_faces.push(face);
                    }
                }
            }
        }

        // For security we should usually drop unsolictied,
        //  but might want to, e.g. keep the ones coming from local faces.
        if is_unsolicited {
            return;
        }

        // Then, if there was actually any interest, we want to store
        //  the data to satisfy future requests.

        // The freshness deadline is the last instant when the data packet will be
        //  considered "fresh" for the purposes of responding to "must be fresh" interests.
        // No freshness_period means the freshness period of 0, i.e. immediately non-fresh.
        let freshness_period = data
            .meta_info
            .map(|mi| mi.freshness_period)
            .flatten()
            .unwrap_or(0);
        let freshness_deadline = now.adding(freshness_period);

        if let Err(err) =
            content_store.insert(data.name, digest, freshness_deadline, original_packet)
        {
            // Handle CS error
        }
    }
}

struct Faces {
    faces: Vec<(u32, FaceEntry)>,
    recv_buffers: Vec<([u8; MAX_PACKET_SIZE], usize)>,
    latest_face_token: u32,
}

impl Faces {
    fn new() -> Self {
        Self {
            faces: Default::default(),
            recv_buffers: Default::default(),
            latest_face_token: 0,
        }
    }

    fn add_face<FS, FR>(&mut self, sender: FS, receiver: FR) -> Option<FaceToken>
    where
        FS: FaceSender + 'static,
        FR: FaceReceiver + 'static,
    {
        let token = self.latest_face_token.checked_add(1)?;
        let entry = FaceEntry {
            sender: Box::new(sender),
            receiver: Box::new(receiver),
        };
        self.faces.push((token, entry));
        self.recv_buffers.push(([0u8; MAX_PACKET_SIZE], 0));
        Some(FaceToken(token))
    }

    fn remove_face(&mut self, token: FaceToken) -> bool {
        // Want to ensure we _consume_ the token (and can thus reuse the index)
        if let Some(idx) = Self::find_face(&self.faces, &token) {
            self.faces.remove(idx);
            self.recv_buffers.remove(idx);
            true
        } else {
            false
        }
    }

    fn len(&self) -> usize {
        self.faces.len()
    }

    fn find_face(faces: &[(u32, FaceEntry)], token: &FaceToken) -> Option<usize> {
        // Can do binary search because we always push higher ids to the end
        faces.binary_search_by_key(&token.0, |x| x.0).ok()
    }
}

const MAX_PACKET_SIZE: usize = 8192;

const DEFAULT_DEADLINE_INCREMENT_MS: u64 = 4000; // 4 sec
const RETRANSMISSION_PERIOD_MS: u64 = 1000; // 1 sec

const TLV_TYPE_INTEREST: u32 = 5;
const TLV_TYPE_DATA: u32 = 6;

struct FaceEntry {
    sender: Box<dyn FaceSender>,
    receiver: Box<dyn FaceReceiver>,
}

impl FaceEntry {
    fn try_recv(
        &mut self,
        recv_buffer: &mut [u8],
        recv_buffer_cursor: &mut usize,
    ) -> Result<usize, FaceError> {
        let bytes_received = self
            .receiver
            .try_recv(&mut recv_buffer[*recv_buffer_cursor..])?;
        assert!(*recv_buffer_cursor + bytes_received <= MAX_PACKET_SIZE);
        *recv_buffer_cursor += bytes_received;
        Ok(bytes_received)
    }

    fn send(&mut self, packet: &[u8]) -> Result<(), FaceError> {
        let len = packet.len();
        let mut sent_so_far = 0;
        while sent_so_far < len {
            sent_so_far += self
                .sender
                .send(&packet[sent_so_far..(len - sent_so_far)])?;
        }
        Ok(())
    }
}
