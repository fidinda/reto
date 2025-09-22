use alloc::{boxed::Box, vec::Vec};

use crate::{
    clock::Clock,
    face::{FaceError, FaceReceiver, FaceSender},
    hash::{Hasher, Sha256Digest},
    io::Write,
    name::Name,
    packet::{Data, Interest},
    tables::Tables,
    tlv::{DecodingError, TlvEncode, VarintDecodingError, TLV},
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaceToken(pub(crate) u32);

pub enum ForwarderError {
    NothingToForward,
    FaceNotfound,
    FaceDisconnected(FaceToken),
    FaceUnrecoverableError(FaceToken, DecodingError),
}

pub trait ForwarderMetrics {
    fn interest_received(&mut self, _from_face: FaceToken) {}
    fn interest_dropped(&mut self, _from_face: FaceToken) {}
    fn interest_satisfied(&mut self, _from_face: FaceToken) {}
    fn interest_timed_out(&mut self, _from_face: FaceToken) {}
    fn interest_sent(&mut self, _to_face: FaceToken) {}

    fn data_received(&mut self, _from_face: FaceToken) {}
    fn data_sent(&mut self, _to_face: FaceToken) {}
    fn data_dropped(&mut self, _from_face: FaceToken) {}

    fn invalid_packet_received(&mut self, _from_face: FaceToken) {}

    // TODO: probably count how many data from cache vs
    // TODO: add bytes
}

pub struct InertMetrics {}

impl ForwarderMetrics for InertMetrics {}

pub const MAX_PACKET_SIZE: usize = 8800;

pub struct Forwarder<C, H, M, T>
where
    C: Clock,
    H: Hasher<Digest = Sha256Digest>,
    M: ForwarderMetrics,
    T: Tables,
{
    faces: Faces,
    tables: T,
    metrics: M,
    clock: C,
    hasher: H,
    last_checked_face: usize,
}

impl<C, H, M, T> Forwarder<C, H, M, T>
where
    C: Clock,
    H: Hasher<Digest = Sha256Digest>,
    M: ForwarderMetrics,
    T: Tables,
{
    pub fn new(clock: C, hasher: H, metrics: M, tables: T) -> Self {
        let faces = Faces::new();

        Self {
            faces,
            tables,
            metrics,
            clock,
            hasher,
            last_checked_face: 0,
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
        self.tables.unregister_face(token);
        self.faces.remove_face(token)
    }

    pub fn next_face_token(&self) -> Option<FaceToken> {
        Some(FaceToken(self.faces.next_face_token()?))
    }

    pub fn register_name_prefix_for_forwarding<'a>(
        &mut self,
        name_prefix: Name<'a>,
        forward_to: FaceToken,
        cost: u32,
    ) {
        self.tables.register_prefix(name_prefix, forward_to, cost)
    }

    pub fn unregister_name_prefix_for_forwarding<'a>(
        &mut self,
        name_prefix: Name<'a>,
        forward_to: FaceToken,
    ) -> bool {
        self.tables.unregister_prefix(name_prefix, forward_to)
    }

    pub fn try_forward_from_face(&mut self, face: FaceToken) -> Result<(), ForwarderError> {
        let ret = if let Some(index) = Faces::find_face(&self.faces.faces, &face) {
            if self.try_recv_from_face_at_index(index)? {
                Ok(())
            } else {
                Err(ForwarderError::NothingToForward)
            }
        } else {
            Err(ForwarderError::FaceNotfound)
        };
        self.tables.prune_if_needed(self.clock.now());
        ret
    }

    pub fn try_forward_from_any_face(&mut self) -> Result<FaceToken, ForwarderError> {
        let mut ret = Err(ForwarderError::NothingToForward);
        for _ in 0..self.faces.len() {
            self.last_checked_face = (self.last_checked_face + 1) % self.faces.len();
            if self.try_recv_from_face_at_index(self.last_checked_face)? {
                ret = Ok(FaceToken(self.faces.faces[self.last_checked_face].0));
            }
        }
        self.tables.prune_if_needed(self.clock.now());
        ret
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
                Err(err) => return Err(ForwarderError::FaceUnrecoverableError(origin, err)),
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
            Err(DecodingError::CannotDecodeValue { len, .. }) => {
                if len > MAX_PACKET_SIZE {
                    // TODO: should skip too-large packets, probably
                }
                return Ok(false);
            }
            Err(err) => return Err(ForwarderError::FaceUnrecoverableError(origin, err)),
        };

        // If we are here, we could process the full packet
        let mut any_processed = false;
        match tlv.typ.get() {
            Interest::TLV_TYPE => {
                // Handle interest
                if let Some(interest) = Interest::try_decode(tlv.val) {
                    Self::handle_interest(
                        interest,
                        &recv_buffer[0..tlv_len],
                        origin,
                        &mut self.tables,
                        &mut self.metrics,
                        &mut self.clock,
                        &mut self.faces.faces,
                    );
                    any_processed = true;
                } else {
                    // Otherwise ignore the malformed packet
                    self.metrics.invalid_packet_received(origin);
                }
            }
            Data::TLV_TYPE => {
                // Handle data
                if let Some(data) = Data::try_decode(tlv.val) {
                    Self::handle_data(
                        data,
                        &recv_buffer[0..tlv_len],
                        origin,
                        &mut self.tables,
                        &mut self.metrics,
                        &mut self.clock,
                        &mut self.hasher,
                        &mut self.faces.faces,
                    );
                    any_processed = true;
                } else {
                    // Otherwise ignore the malformed packet
                    self.metrics.invalid_packet_received(origin);
                }
            }
            _ => {
                self.metrics.invalid_packet_received(origin);
            } // Otherwise we ignore the packet
        }

        // Reset the cursor back by the size of the processed element
        if tlv_len < *recv_buffer_cursor {
            // There are still some unprocessed bytes
            recv_buffer.copy_within(tlv_len..*recv_buffer_cursor, 0);
            *recv_buffer_cursor -= tlv_len;
        } else {
            // We are done with this bunch of bytes
            *recv_buffer_cursor = 0;
        }

        Ok(any_processed)
    }

    fn handle_interest<'a>(
        mut interest: Interest<'a>,
        original_packet: &'a [u8],
        origin: FaceToken,
        tables: &mut T,
        metrics: &mut M,
        clock: &mut C,
        faces: &mut [(u32, FaceEntry)],
    ) {
        // Interest must have a non-empty name
        if interest.name.component_count() == 0 {
            metrics.interest_dropped(origin);
            return;
        };

        // We drop all the interests without a nonce, since
        //  we don't know which faces are local
        let nonce = match interest.nonce {
            Some(nonce) => nonce.bytes,
            None => {
                metrics.interest_dropped(origin);
                return;
            }
        };

        // We want to drop packets if they have hop limit of 0,
        //  otherwise we want to decrement it. If the resulting
        //  hop limit is 0 we will only try to satisfy this from
        //  the content store, but not forward.
        // If no hop limit is present we always accept the interest.
        let is_last_hop = match &interest.hop_limit {
            Some(hop) => {
                if hop.val == 0 {
                    metrics.interest_dropped(origin);
                    return;
                } else {
                    hop.val == 1
                }
            }
            None => false,
        };

        let now = clock.now();

        // First we try to satisfy the interest from our local cache
        if let Some(retrieved) = tables.get_data(
            interest.name,
            interest.can_be_prefix.is_some(),
            interest.must_be_fresh.is_some(),
            now,
        ) {
            // The packet is found so we simply reply to the same face
            if let Some(index) = Faces::find_face(&faces, &origin) {
                metrics.interest_satisfied(origin);
                metrics.data_sent(origin);
                faces[index].1.send_whole_packet(retrieved)
            }
            return;
        }

        // If this is the last hop for the interest we return, since we could only
        //  try to satisfy it locally.
        if is_last_hop {
            metrics.interest_dropped(origin);
            return;
        }

        // We need to decrement the hop byte if it is present
        let hop_value_and_byte_idx = if let Some(v) = interest.hop_limit.as_mut() {
            v.val = v.val.saturating_sub(1);
            let hop_val = v.val;
            if let Some(idx) = interest.index_of_hop_byte_in_encoded_tlv() {
                Some((hop_val, idx))
            } else {
                None
            }
        } else {
            None
        };

        let interest_lifetime = interest.interest_lifetime.map(|x| x.val);
        for next_hop in tables.register_interest(
            interest.name,
            interest.can_be_prefix.is_some(),
            interest_lifetime,
            nonce,
            origin,
            now,
        ) {
            // Never forward back to the same face
            if next_hop == origin {
                continue;
            }
            if let Some(index) = Faces::find_face(&faces, &next_hop) {
                metrics.interest_sent(next_hop);
                if let Some((hop, idx)) = hop_value_and_byte_idx {
                    // Use the original packet, but substituting the byte at index
                    faces[index]
                        .1
                        .send_modified_packet(original_packet, &[(idx, idx + 1, &[hop])])
                } else {
                    // Use the original packet
                    faces[index].1.send_whole_packet(&original_packet)
                }
            }
        }
    }

    fn handle_data<'a>(
        data: Data<'a>,
        original_packet: &'a [u8],
        origin: FaceToken,
        tables: &mut T,
        metrics: &mut M,
        clock: &mut C,
        hasher: &mut H,
        faces: &mut [(u32, FaceEntry)],
    ) {
        let mut is_unsolicited: bool = true;

        let now = clock.now();

        // We set up a way to compute the digest of the packet,
        //  but only if actually needed.
        let mut digest = None;
        let mut digest_computation = || match digest {
            Some(inner) => inner,
            None => {
                hasher.reset();
                hasher.update(original_packet);
                let inner = hasher.finalize_reset().0;
                digest = Some(inner);
                inner
            }
        };

        // First we try to find the interest in the PIT and send it to every
        //  requesting face other than the face we got it from.
        for face in tables.satisfy_interests(data.name, now, &mut digest_computation) {
            is_unsolicited = false;
            if face != origin {
                if let Some(index) = Faces::find_face(&faces, &face) {
                    metrics.interest_satisfied(face);
                    metrics.data_sent(face);
                    faces[index].1.send_whole_packet(original_packet)
                }
            }
        }

        // For security we should drop the unsolicited data
        if is_unsolicited {
            metrics.data_dropped(origin);
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
            .map(|fp| fp.val)
            .unwrap_or(0);

        let digest = digest_computation();
        tables.insert_data(data.name, digest, freshness_period, now, original_packet)
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
        let token = self.next_face_token()?;
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

    pub fn next_face_token(&self) -> Option<u32> {
        self.latest_face_token.checked_add(1)
    }

    fn len(&self) -> usize {
        self.faces.len()
    }

    fn find_face(faces: &[(u32, FaceEntry)], token: &FaceToken) -> Option<usize> {
        // Can do binary search because we always push higher ids to the end
        faces.binary_search_by_key(&token.0, |x| x.0).ok()
    }
}

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
        debug_assert!(*recv_buffer_cursor + bytes_received <= MAX_PACKET_SIZE);
        *recv_buffer_cursor += bytes_received;
        Ok(bytes_received)
    }

    fn send_whole_packet(&mut self, packet: &[u8]) {
        if let Err(FaceError::Disconnected) = self.sender.write(&packet) {
            self.should_close = true;
            return;
        }
        if let Err(FaceError::Disconnected) = self.sender.flush() {
            self.should_close = true;
            return;
        }
    }

    fn send_modified_packet(
        &mut self,
        packet: &[u8],
        ranges_and_replacements: &[(usize, usize, &[u8])],
    ) {
        let mut offset = 0;

        for &(start, end, replacement) in ranges_and_replacements {
            debug_assert!(start >= offset && end >= start);
            if start > offset {
                if let Err(FaceError::Disconnected) = self.sender.write(&packet[offset..start]) {
                    self.should_close = true;
                    return;
                }
            }
            if let Err(FaceError::Disconnected) = self.sender.write(replacement) {
                self.should_close = true;
                return;
            }
            offset = end;
        }

        if offset < packet.len() {
            if let Err(FaceError::Disconnected) = self.sender.write(&packet[offset..]) {
                self.should_close = true;
                return;
            }
        }

        if let Err(FaceError::Disconnected) = self.sender.flush() {
            self.should_close = true;
            return;
        }
    }
}
