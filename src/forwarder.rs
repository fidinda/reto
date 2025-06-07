use core::marker::PhantomData;

use alloc::{boxed::Box, vec::Vec};

use crate::{
    clock::Clock,
    face::{FaceError, FaceReceiver, FaceSender},
    hash::{Digest, Hasher, Sha256Digest},
    name::Name,
    packet::{Data, Interest},
    store::ContentStore,
    tables::{PrefixRegistrationResult, Tables},
    tlv::{DecodingError, Encode, VarintDecodingError, TLV},
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaceToken(pub(crate) u32);

pub enum ForwarderError {
    NothingToForward,
    FaceNotfound,
    FaceDisconnected(FaceToken),
    FaceUnrecoverableError(DecodingError),
}

pub struct Forwarder<CS, C, H>
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

    pub fn try_forward(&mut self, face_to_use: Option<&FaceToken>) -> Result<(), ForwarderError> {
        if let Some(token) = face_to_use {
            // If we were given an explicit face to try we try it
            if let Some(index) = Faces::find_face(&self.faces.faces, token) {
                if self.try_recv_from_face_at_index(index)? {
                    Ok(())
                } else {
                    Err(ForwarderError::NothingToForward)
                }
            } else {
                Err(ForwarderError::FaceNotfound)
            }
        } else {
            // Otherwise we try all the faces in turn
            for _ in 0..self.faces.len() {
                self.last_checked_face = if self.last_checked_face >= self.faces.len() {
                    0
                } else {
                    self.last_checked_face + 1
                };
                if self.try_recv_from_face_at_index(self.last_checked_face)? {
                    return Ok(());
                }
            }
            Err(ForwarderError::NothingToForward)
        }
    }

    fn try_recv_from_face_at_index(&mut self, index: usize) -> Result<bool, ForwarderError> {
        let (token, entry) = &mut self.faces.faces[index];
        let origin = FaceToken(*token);

        if entry.should_close {
            return Err(ForwarderError::FaceDisconnected(origin));
        }

        let (recv_buffer, recv_buffer_cursor) = &mut self.faces.recv_buffers[index];

        let mut should_try_recv = true;

        // First, it could be possible that we already have a ready packet in buffer from last recv
        // If so we will not try to receive new data
        if *recv_buffer_cursor > 0 {
            match TLV::try_decode(&recv_buffer[0..*recv_buffer_cursor]) {
                Ok(_) => should_try_recv = false,
                // If we have too few bytes this could be solved with a recv
                Err(DecodingError::CannotDecodeType {
                    err: VarintDecodingError::BufferTooShort,
                }) => {}
                Err(DecodingError::CannotDecodeLength {
                    err: VarintDecodingError::BufferTooShort,
                    ..
                }) => {}
                Err(DecodingError::CannotDecodeValue { .. }) => {}
                Err(err) => return Err(ForwarderError::FaceUnrecoverableError(err)),
            }
        }

        if should_try_recv {
            match entry.try_recv(recv_buffer, recv_buffer_cursor) {
                Ok(bytes_received) => {
                    if bytes_received == 0 {
                        return Ok(false); // Nothing was received, the face is not ready
                    }
                }
                Err(FaceError::Disconnected) => {
                    return Err(ForwarderError::FaceDisconnected(origin))
                }
            }
        }

        let (tlv, tlv_len) = match TLV::try_decode(&recv_buffer[0..*recv_buffer_cursor]) {
            Ok((tlv, tlv_len)) => (tlv, tlv_len),
            // If we have too few bytes this could be solved with a recv
            Err(DecodingError::CannotDecodeType {
                err: VarintDecodingError::BufferTooShort,
            }) => return Ok(false),
            Err(DecodingError::CannotDecodeLength {
                err: VarintDecodingError::BufferTooShort,
                ..
            }) => return Ok(false),
            Err(DecodingError::CannotDecodeValue { .. }) => return Ok(false),
            Err(err) => return Err(ForwarderError::FaceUnrecoverableError(err)),
        };

        // If we are here, we could process the full packet
        let mut any_processed = false;
        match tlv.typ.get() {
            TLV_TYPE_INTEREST => {
                let name_offset = (tlv.typ.get() as u64).encoded_length()
                    + (tlv.val.len() as u64).encoded_length();
                // Handle interest
                if let Some(interest) = Interest::from_bytes(tlv.val) {
                    if let Some((index_of_hop_byte, new_nonce)) = Self::handle_interest(
                        interest,
                        origin,
                        &mut self.tables,
                        &mut self.content_store,
                        &mut self.clock,
                        &mut self.faces.faces,
                    ) {
                        let packet_len = tlv_len;
                        if let Some(hop_byte_index) = index_of_hop_byte {
                            recv_buffer[hop_byte_index] =
                                recv_buffer[hop_byte_index].saturating_sub(1);
                        }
                        if let Some(new_nonce) = new_nonce {
                            // TODO: we should set this nonce and possibly re-encode the whole packet
                            //  as its size's size could have changed. But, could optimize too.
                        }

                        let name = Name::from_bytes(&recv_buffer[name_offset..*recv_buffer_cursor])
                            .unwrap();
                        Self::dispatch_interest(
                            name,
                            &recv_buffer[0..packet_len],
                            origin,
                            &mut self.tables,
                            &mut self.faces.faces,
                        );
                    }
                    any_processed = true;
                } // Otherwise ignore the malformed packet
            }
            TLV_TYPE_DATA => {
                // Handle data
                if let Some(data) = Data::from_bytes(tlv.val) {
                    Self::handle_data(
                        data,
                        &tlv.val,
                        origin,
                        &mut self.tables,
                        &mut self.content_store,
                        &mut self.clock,
                        &mut self.faces.faces,
                    );
                    any_processed = true;
                } // Otherwise ignore the malformed packet
            }
            _ => {} // Otherwise we ignore the packet
        }

        // Reset the cursor back by the size of the processed element
        if tlv_len < *recv_buffer_cursor {
            // There are still some unprocessed bytes, so we want to loop again
            recv_buffer.copy_within(tlv_len..*recv_buffer_cursor, 0);
            *recv_buffer_cursor -= tlv_len;
        } else {
            // We are done with this bunch of bytes
            *recv_buffer_cursor = 0;
        }

        Ok(any_processed)
    }

    // Returns the modifications needed to the interest
    // If Some, we should check for hop_limit and if the
    //  inner oprion is Some, also set the new nonce
    fn handle_interest<'a>(
        interest: Interest<'a>,
        origin: FaceToken,
        tables: &mut Tables,
        content_store: &mut CS,
        clock: &mut C,
        faces: &mut [(u32, FaceEntry)],
    ) -> Option<(Option<usize>, Option<[u8; 4]>)> {
        // Interest must have a non-empty name
        if interest.name.component_count() == 0 {
            return None;
        };

        // We want to drop packets if they have hop limit of 0,
        //  otherwise we want to decrement it. If the resulting
        //  hop limit is 0 we will only try to satisfy this from
        //  the content store, but not forward.
        // If no hop limit is present we always accept the interest.
        let is_last_hop = match &interest.hop_limit {
            Some(hop) => {
                if *hop == 0 {
                    return None;
                } else {
                    *hop == 1
                }
            }
            None => false,
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
                        return None;
                    }
                }
                PrefixRegistrationResult::DeadNonce => {
                    // The interest likely looped, so we drop it
                    return None;
                }
                PrefixRegistrationResult::InvalidName => {
                    // The interest has an invalid name, so we drop it
                    return None;
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
                    faces[index].1.should_close = true;
                }
            }
            return None;
        }

        // Finally, if this is not the last hop of the interest we try to forward it.
        if !is_last_hop {
            // If the interest is missing a nonce we should add one before forwarding
            // But do not for now, since it requires re-encoding the interest
            let mut new_nonce = None;
            if interest.nonce.is_none() {
                new_nonce = Some(tables.next_nonce());
            }

            let index_of_hop_byte = interest.index_of_hop_byte();

            return Some((index_of_hop_byte, new_nonce));
        }

        None
    }

    fn dispatch_interest<'a>(
        name: Name<'a>,
        original_packet: &'a [u8],
        origin: FaceToken,
        tables: &mut Tables,
        faces: &mut [(u32, FaceEntry)],
    ) {
        // We now know we need to forward the interest, just need to check where to send it
        // The strategy we use is basically multicast to all relevant faces, nothing complex.
        for next_hop in tables.hops_for_name(name) {
            // Never forward back to the same face
            if next_hop != origin {
                if let Some(index) = Faces::find_face(&faces, &next_hop) {
                    if let Err(FaceError::Disconnected) = faces[index].1.send(&original_packet) {
                        faces[index].1.should_close = true;
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
    ) {
        let mut is_unsolicited: bool = true;

        let now = clock.now();

        let mut hasher = H::new();
        // TODO: test this!!! Probably inside the tlv, not packet?
        let range = data.signed_range_in_parent_tlv();
        hasher.update(&original_packet[range.0..range.1]);
        let digest = hasher.finalize().into_inner();

        // First we try to find the interest in the PIT and send it to every
        //  requesting face other than the face we got it from.
        for face in tables.satisfy_interests(data.name, digest, now) {
            is_unsolicited = false;
            if face != origin {
                if let Some(index) = Faces::find_face(&faces, &face) {
                    if let Err(FaceError::Disconnected) = faces[index].1.send(original_packet) {
                        faces[index].1.should_close = true;
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
            should_close: false,
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

const MAX_PACKET_SIZE: usize = 8800;

const DEFAULT_DEADLINE_INCREMENT_MS: u64 = 4000; // 4 sec
const RETRANSMISSION_PERIOD_MS: u64 = 1000; // 1 sec

const TLV_TYPE_INTEREST: u32 = 5;
const TLV_TYPE_DATA: u32 = 6;

struct FaceEntry {
    sender: Box<dyn FaceSender>,
    receiver: Box<dyn FaceReceiver>,
    should_close: bool,
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
