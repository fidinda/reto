use crate::encode::{Encodable, SliceBuffer};
use crate::tables::{PrefixRegistrationResult, Tables};
use crate::{
    parse_packet, ContentStore, Data, DecodingError, FaceError, FaceReceiver, FaceSender, Hasher,
    Interest, Name, PacketParseResult, Platform,
};
use alloc::{boxed::Box, rc::Rc};
use core::cell::RefCell;
use core::future::Future;
use futures_util::{Stream, StreamExt, Sink, SinkExt};

pub trait ControlMessage {
    fn apply_to_forwarder<CS, P, NS, NSE>(self, forwarder: &mut Forwarder<CS, P, NS, NSE>)
    where
        CS: ContentStore,
        P: Platform,
        NS: Sink<ForwarderNotification, Error = NSE> + 'static,
        NSE : 'static;
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaceHandle(pub(crate) u32);

pub enum  ForwarderNotification {
    FaceDisconnected(FaceHandle)
}

pub struct Forwarder<CS, P, NS, NSE>
where
    CS: ContentStore + 'static,
    P: Platform + 'static,
    NS: Sink<ForwarderNotification, Error = NSE> + 'static,
    NSE : 'static,
{
    platform: P,
    inner: Rc<RefCell<ForwarderInner<CS,P, NS, NSE>>>,
}

struct ForwarderInner<CS, P, NS, NSE> 
where
CS: ContentStore + 'static,
P: Platform + 'static, 
NS: Sink<ForwarderNotification, Error = NSE> + 'static,
NSE : 'static,
{
    faces: Faces<P, MAX_FACE_COUNT>,
    cs: CS,
    tables: Tables,
    notification_sender: Pin<Box<NS>>,
}


const MAX_PACKET_SIZE: usize = 8192;
const MAX_FACE_COUNT: usize = 256;

impl<CS, P, NS, NSE> Forwarder<CS, P, NS, NSE>
where
    CS: ContentStore + 'static,
    P: Platform + 'static,
    NS: Sink<ForwarderNotification, Error = NSE> + 'static,
    NSE : 'static,
{
    pub async fn run<M, CR>(cs: CS, control_receiver: CR, notification_sender: NS, platform: P)
    where
        M: ControlMessage,
        CR: Stream<Item = M>,
    {
        let mut control_receiver = Box::pin(control_receiver);
        
        let inner = ForwarderInner {
            faces: Faces::new(),
            cs,
            tables: Tables::new(),
            notification_sender: Box::pin(notification_sender),
        };
        
        let mut forwarder = Self {
            platform,
            inner: Rc::new(RefCell::new(inner)),
        };

        //notification_sender.send(ForwarderNotification::FaceDisconnected(FaceHandle(0))).await;

        loop {
            match control_receiver.next().await {
                Some(m) => m.apply_to_forwarder(&mut forwarder),
                None => break, // The control channel is dropped, so we stop the forwarder
            }
        }
    }

    pub fn add_face<FS, FR>(&mut self, sender: FS, receiver: FR) -> Option<FaceHandle>
    where
        FS: FaceSender + 'static,
        FR: FaceReceiver + 'static,
    {
        let inner = Rc::clone(&self.inner);
        let face = inner.as_ref().borrow_mut().faces.next_handle();

        let task = self.platform.spawn(async move {
            let mut receiver = receiver;

            let mut buffer = [0u8; MAX_PACKET_SIZE];
            let mut buffer_cursor = 0;

            let mut faces_of_interest = [FaceHandle(0); MAX_FACE_COUNT];

            loop {
                match receiver.recv(&mut buffer[buffer_cursor..]).await {
                    Ok(len) => {
                        buffer_cursor += len;
                        let mut processed_len = 0;
                        for parse_result in crate::parse_tlvs(&buffer) {
                            match parse_result {
                                Ok(entry) => {
                                    let mut original_packet =
                                        &mut buffer[entry.byte_range.0..entry.byte_range.1];
                                    match parse_packet(entry.tlv) {
                                        PacketParseResult::Interest(interest) => {
                                            Self::handle_interest(
                                                interest,
                                                &mut original_packet,
                                                face,
                                                &mut *inner.borrow_mut(),
                                                &mut faces_of_interest,
                                            )
                                            .await
                                        }
                                        PacketParseResult::Data(data) => {
                                            Self::handle_data(
                                                data,
                                                original_packet,
                                                face,
                                                &mut *inner.borrow_mut(),
                                                &mut faces_of_interest,
                                            )
                                            .await
                                        }
                                        PacketParseResult::UnknownType(non_zero) => todo!(),
                                        PacketParseResult::TLVDecodingError(decoding_error) => {
                                            todo!()
                                        }
                                        PacketParseResult::PacketDecodingError => todo!(),
                                    }
                                    processed_len = entry.byte_range.1;
                                }
                                Err(e) => match e {
                                    DecodingError::BufferTooShort => break,
                                    DecodingError::NonMinimalIntegerEncoding => todo!(),
                                    DecodingError::TypeInvalid => todo!(),
                                    DecodingError::LengthInvalid => todo!(),
                                },
                            }
                        }

                        if buffer_cursor > processed_len {
                            buffer.copy_within(processed_len..buffer_cursor, 0);
                        }
                        buffer_cursor -= processed_len;
                    }
                    Err(FaceError::Disconnected) => {
                        Self::remove_face_inner(face, &mut *inner.borrow_mut());
                        break;
                    }
                };
            }
        });

        self.inner
            .as_ref()
            .borrow_mut()
            .faces
            .add_face(face, task, sender)
    }

    pub fn remove_face(&mut self, face: FaceHandle) {
        Self::remove_face_inner(face, &mut *self.inner.borrow_mut())
    }

    fn remove_face_inner(
        face: FaceHandle,
        inner: &mut ForwarderInner<CS, P, NS, NSE>,
    ) {
        inner.tables.unregister_face(face);
        inner.faces.remove_face(face);
    }

    pub fn register_name_prefix_for_forwarding<'a>(
        &mut self,
        name_prefix: Name<'a>,
        forward_to: FaceHandle,
    ) {
        self.inner
            .as_ref()
            .borrow_mut()
            .tables
            .register_prefix(name_prefix, forward_to)
    }

    pub fn unregister_name_prefix_for_forwarding<'a>(
        &mut self,
        name_prefix: Name<'a>,
        forward_to: FaceHandle,
    ) -> bool {
        self.inner
            .as_ref()
            .borrow_mut()
            .tables
            .unregister_prefix(name_prefix, forward_to)
    }

    async fn send_to(
        face: FaceHandle,
        packet: &[u8],
        inner: &mut ForwarderInner<CS, P, NS, NSE>,
    ) {
        let len = packet.len();
        let mut sent_so_far = 0;
        while sent_so_far < len {
            match inner.faces
                .send_to(face, &packet[sent_so_far..(len - sent_so_far)])
                .await
            {
                Ok(sent) => sent_so_far += sent,
                Err(FaceError::Disconnected) => Self::remove_face_inner(face, inner),
            }
        }
    }

    async fn handle_interest<'a>(
        mut interest: Interest<'a>,
        original_packet: &'a mut [u8],
        origin: FaceHandle,
        inner: &mut ForwarderInner<CS, P, NS, NSE>,
        faces_of_interest: &mut [FaceHandle],
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
        let (is_last_hop, hop_needs_decrement) = match &mut interest.hop_limit {
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

        let now = P::now();

        if !is_last_hop {
            let deadline = match interest.interest_lifetime {
                Some(ms) => now.adding(ms),
                None => now.adding(DEFAULT_DEADLINE_INCREMENT_MS),
            };

            match inner.tables.register_interest(
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

        if let Ok(Some(retrieved)) = inner.cs
            .get(interest.name, interest.can_be_prefix, freshness_requirement)
            .await
        {
            // The packet is found so we simply reply to the same face
            Self::send_to(origin, retrieved, inner).await;
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
                    original_packet[hop_byte_index] = original_packet[hop_byte_index].saturating_sub(1);
                }
            }

            // We now know we need to forward the interest, just need to check where to send it
            // The strategy we use is basically multicast to all relevant faces, nothing complex.
            let mut faces_to_send_to = 0;
            for next_hop in inner.tables.hops_for_name(interest.name) {
                // Never forward back to the same face
                if next_hop != origin {
                    faces_of_interest[faces_to_send_to] = next_hop;
                    faces_to_send_to += 1;
                }
            }

            for i in 0..faces_to_send_to {
                Self::send_to(faces_of_interest[i], original_packet, inner).await
            }
        }
    }

    async fn handle_data<'a>(
        data: Data<'a>,
        original_packet: &'a [u8],
        origin: FaceHandle,
        inner: &mut ForwarderInner<CS, P, NS, NSE>,
        faces_of_interest: &mut [FaceHandle],
    ) {
        let mut is_unsolicited: bool = true;

        let now = P::now();

        let mut hasher = P::sha256hasher();
        // TODO: test this!!! Probably inside the tlv, not packet?
        hasher.update(
            &original_packet[data.signed_range_in_parent_tlv.0..data.signed_range_in_parent_tlv.1],
        );
        let digest = hasher.finalize();

        // First we try to find the interest in the PIT and send it to every
        //  requesting face other than the face we got it from.
        let mut faces_to_send_to = 0;
        for face in inner.tables
            .satisfy_interests(data.name, digest, now)
        {
            is_unsolicited = false;
            if face != origin {
                faces_of_interest[faces_to_send_to] = face;
                faces_to_send_to += 1;
            }
        }

        for i in 0..faces_to_send_to {
            Self::send_to(faces_of_interest[i], original_packet, inner).await
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

        if let Err(err) = inner.cs
            .insert(data.name, digest, freshness_deadline, original_packet)
            .await
        {
            // Handle CS error
        }
    }
}

struct Faces<P: Platform + 'static, const FC: usize> {
    handles: [Option<(
        FaceHandle,
        <P as Platform>::Task<()>,
        Box<dyn FaceSenderWrap>,
    )>; FC],
    count: usize,
    next_id: u32,
}

impl<P: Platform, const FC: usize> Faces<P, FC> {
    fn new() -> Self {
        Self {
            handles: [const { None }; FC],
            count: 0,
            next_id: 0,
        }
    }

    fn next_handle(&mut self) -> FaceHandle {
        let id = self.next_id;
        self.next_id += 1;
        FaceHandle(id)
    }

    fn add_face<FS: FaceSender + 'static>(
        &mut self,
        handle: FaceHandle,
        task: <P as Platform>::Task<()>,
        sender: FS,
    ) -> Option<FaceHandle> {
        if self.count == MAX_FACE_COUNT {
            return None;
        }
        self.handles[self.count] = Some((handle, task, Box::new(FaceSenderWrapper { sender })));
        self.count += 1;
        self.handles[0..self.count]
            .sort_by(|a, b| a.as_ref().unwrap().0.cmp(&b.as_ref().unwrap().0));
        Some(handle)
    }

    fn remove_face(&mut self, face: FaceHandle) {
        if let Some(idx) = self.index_of_face(face) {
            // Move all handles back
            for i in idx..(self.count - 1) {
                self.handles[i] = self.handles[i + 1].take();
            }
            self.count -= 1;
        }
    }

    fn index_of_face(&self, face: FaceHandle) -> Option<usize> {
        if let Ok(idx) =
            self.handles[0..self.count].binary_search_by(|x| x.as_ref().unwrap().0.cmp(&face))
        {
            return Some(idx);
        }
        None
    }

    async fn send_to(&mut self, face: FaceHandle, packet: &[u8]) -> Result<usize, FaceError> {
        if let Some(idx) = self.index_of_face(face) {
            return self.handles[idx].as_mut().unwrap().2.send(packet).await;
        }
        Err(FaceError::Disconnected)
    }
}

use core::pin::Pin;
trait FaceSenderWrap {
    fn send<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, FaceError>> + 'a>>;
}

struct FaceSenderWrapper<FS>
where
    FS: FaceSender,
{
    sender: FS,
}

impl<FS> FaceSenderWrap for FaceSenderWrapper<FS>
where
    FS: FaceSender,
{
    fn send<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, FaceError>> + 'a>> {
        Box::pin(self.sender.send(&bytes))
    }
}

const DEFAULT_DEADLINE_INCREMENT_MS: u64 = 4000; // 4 sec
const RETRANSMISSION_PERIOD_MS: u64 = 1000; // 1 sec
