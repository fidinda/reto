use alloc::{boxed::Box, rc::Rc, vec::Vec};
use futures_lite::{Stream, StreamExt};
use core::cell::RefCell;
use core::future::Future;
use crate::{parse_packet, ContentStore, Data, FaceError, FaceReceiver, FaceSender, Hasher, Interest, Name, PacketParseResult, Platform};
use crate::tables::{PrefixRegistrationResult, Tables};
use crate::encode::Encodable;

pub trait ControlMessage {
    fn apply_to_forwarder<CS, P>(self, forwarder: &mut Forwarder<CS, P>)
    where CS : ContentStore, P : Platform;
}


#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaceHandle(pub(crate) u32);


pub struct Forwarder<CS, P>
where 
CS : ContentStore + 'static,
P : Platform + 'static {
    platform: P,
    faces: Rc<RefCell<Faces<P>>>,
    cs: Rc<CS>,
    tables: Rc<RefCell<Tables>>
}

impl<CS, P> Forwarder<CS, P> 
where 
CS : ContentStore + 'static,
P : Platform + 'static {
    
    pub async fn run<M, CR>(
        cs: CS,
        control_receiver: CR,
        platform: P,
    ) where 
    M: ControlMessage,
    CR : Stream<Item = M> 
    {
        let mut control_receiver = Box::pin(control_receiver);

        let cs = Rc::new(cs);
        let tables = Rc::new(RefCell::new(Tables::new()));
        
        let faces = Faces { handles: Default::default(), next_id: 0 };
        let faces = Rc::new(RefCell::new( faces ));

        let mut forwarder = Self { 
            platform, 
            faces, 
            tables,
            cs,
        };

        loop {
            match control_receiver.next().await {
                Some(m) => m.apply_to_forwarder(&mut forwarder),
                None => break // The control channel is dropped, so we stop the forwarder
            }
        }
    }
    
    pub fn add_face<FS, FR>(&mut self, sender: FS, receiver: FR) -> FaceHandle
    where FS: FaceSender + 'static, FR: FaceReceiver + 'static {
        let faces = Rc::clone(&self.faces);
        let face = faces.as_ref().borrow_mut().next_handle();
        
        let cs = Rc::clone(&self.cs);
        let tables = Rc::clone(&self.tables);

        let task = self.platform.spawn(async move {
            let mut receiver = receiver;
            let mut interest_buffer = Vec::new();
            loop {
                match receiver.recv().await {
                    Ok(packet) => {
                        match parse_packet(packet) {
                            Some(PacketParseResult::Interest(interest)) => {
                                Self::handle_interest(
                                    interest,
                                    packet, 
                                    face, 
                                    &faces, 
                                    &tables, 
                                    &cs,
                                    &mut interest_buffer
                                ).await
                            },
                            Some(PacketParseResult::Data(data)) => {
                                Self::handle_data(
                                    data,
                                    packet, 
                                    face, 
                                    &faces, 
                                    &tables, 
                                    &cs
                                ).await
                            },
                            _ => {}
                        }
                    },
                    Err(FaceError::Disconnected) => {
                        Self::remove_face_inner(face, &faces, &tables);
                        break
                    },
                };
            }
        });
        
        self.faces.as_ref().borrow_mut().add_face(face, task, sender);

        face
    }

    pub fn remove_face(&mut self, face: FaceHandle) {
        Self::remove_face_inner(face, &self.faces, &self.tables)
    }

    fn remove_face_inner(face: FaceHandle, faces: &Rc<RefCell<Faces<P>>>, tables: &Rc<RefCell<Tables>>) {
        tables.as_ref().borrow_mut().unregister_face(face);
        faces.as_ref().borrow_mut().remove_face(face);
    }



    pub fn register_name_prefix_for_forwarding<'a>(&mut self, name_prefix: Name<'a>, forward_to: FaceHandle) {
        self.tables.as_ref().borrow_mut().register_prefix(name_prefix, forward_to)
    }

    pub fn unregister_name_prefix_for_forwarding<'a>(&mut self, name_prefix: Name<'a>, forward_to: FaceHandle) -> bool {
        self.tables.as_ref().borrow_mut().unregister_prefix(name_prefix, forward_to)
    }



    async fn send_to(face: FaceHandle, packet: &[u8], faces: &Rc<RefCell<Faces<P>>>, tables: &Rc<RefCell<Tables>>) {
        match faces.as_ref().borrow_mut().send_to(face, &packet).await {
            Ok(_) => {},
            Err(FaceError::Disconnected) =>  Self::remove_face_inner(face, &faces, &tables),
        }
    }

    async fn handle_interest<'a>(
        mut interest: Interest<'a>, 
        original_packet: &'a [u8],
        origin: FaceHandle, 
        faces: &'a Rc<RefCell<Faces<P>>>, 
        tables: &'a Rc<RefCell<Tables>>,
        cs: &'a Rc<CS>,
        interest_buffer: &mut Vec<u8>,
    ) {
        // Interest must have a non-empty name
        if interest.name.component_count() == 0 { return };

        // TODO: since this is the only thing we change in an interest
        //  it would be great to be able to write out the original 
        //  interest with only this byte changed.
        let mut interest_modified = false;

        // We want to drop packets if they have hop limit of 0,
        //  otherwise we want to decrement it. If the resulting 
        //  hop limit is 0 we will only try to satisfy this from 
        //  the content store, but not forward.
        // If no hop limit is present we always accept the interest.
        let is_last_hop = match &mut interest.hop_limit {
            Some(hop) => if *hop == 0 { 
                return 
            } else { 
                interest_modified = true;
                *hop -= 1;
                *hop == 0
            },
            None => false
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

            match tables.as_ref().borrow_mut()
            .register_interest(
                interest.name, 
                interest.can_be_prefix,
                origin, 
                now, 
                RETRANSMISSION_PERIOD_MS,
                deadline, 
                interest.nonce
            ) {
                PrefixRegistrationResult::NewRegistration => {
                    // This is the first time (in recent past) that we see this packet, forward through
                },
                PrefixRegistrationResult::PreviousFromSelf => {
                    // We treat this as a retransmission and always send the packet forward
                },
                PrefixRegistrationResult::PreviousFromOthers(should_retransmit) => {
                    // The PIT already has others applying, so we only forward if it was not too long ago
                    if !should_retransmit {
                        return
                    }
                },
                PrefixRegistrationResult::DeadNonce => {
                    // The interest likely looped, so we drop it
                    return
                },
                PrefixRegistrationResult::InvalidName => {
                    // The interest has an invalid name, so we drop it
                    return
                }
            }
        }

        // Then we try to satisfy the interest from our local cache
        let freshness_requirement = if interest.must_be_fresh {
            Some(now)
        } else {
            None
        }; 

        if let Ok(Some(retrieved)) = cs.as_ref()
        .get(interest.name, interest.can_be_prefix, freshness_requirement).await {
            // The packet is found so we simply reply to the same face
            Self::send_to(origin, retrieved, &faces, &tables).await;
            return;
        }

        // Finally, if this is not the last hop of the interest we try to forward it.
        if !is_last_hop {
            // If the interest is missing a nonce we add one before forwarding
            if interest.nonce.is_none() {
                let nonce = tables.as_ref().borrow_mut().next_nonce();
                interest.nonce = Some(nonce);
                interest_modified = true;
            }

            // If the interest has been modified we need to encode it
            let encoded_interest = if interest_modified {
                interest_buffer.clear();
                match interest.encode(interest_buffer) {
                    Ok(_) => {},
                    Err(_) => return
                }
                &interest_buffer
            } else {
                original_packet
            };

            // We now know we need to forward the interest, just need to check where to send it
            // The strategy we use is basically multicast to all relevant faces, nothing complex.
            for next_hop in tables.as_ref().borrow_mut().hops_for_name(interest.name) {
                // Never forward back to the same face
                if next_hop != origin {
                    Self::send_to(next_hop, encoded_interest, &faces, &tables).await
                }
            }
        }
    }

    async fn handle_data<'a>(
        data: Data<'a>, 
        original_packet: &'a [u8],
        origin: FaceHandle, 
        faces: &'a Rc<RefCell<Faces<P>>>, 
        tables: &'a Rc<RefCell<Tables>>,
        cs: &'a Rc<CS>,
    ) {
        let mut is_unsolicited: bool = true;

        let now = P::now();

        let mut hasher = P::sha256hasher();
        // TODO: test this!!! Probably inside the tlv, not packet?
        hasher.update(&original_packet[data.signed_range_in_parent_tlv.0..data.signed_range_in_parent_tlv.1]);
        let digest = hasher.finalize();

        // First we try to find the interest in the PIT and send it to every 
        //  requesting face other than the face we got it from.
        for face in tables.as_ref().borrow_mut().satisfy_interests(data.name, digest, now) {
            is_unsolicited = false;
            if face != origin {
                Self::send_to(face, original_packet, &faces, &tables).await
            }
        }

        // For security we should usually drop unsolictied,
        //  but might want to, e.g. keep the onces coming from local faces.    
        if is_unsolicited {
            return
        }

        // Then, if there was actually any interest, we want to store 
        //  the data to satisfy future requests.
        
        // The freshness deadline is the last instant when the data packet will be 
        //  considered "fresh" for the purposes of responding to "must be fresh" interests. 
        // No freshness_period means the freshness period of 0, i.e. immediately non-fresh.
        let freshness_period = data.meta_info
        .map(|mi| mi.freshness_period)
        .flatten()
        .unwrap_or(0);
        let freshness_deadline = now.adding(freshness_period);

        let _ = cs.as_ref().insert(data.name, digest, freshness_deadline, original_packet).await;
    }

}


struct Faces<P : Platform + 'static> {
    handles: Vec<(FaceHandle, <P as Platform>::Task<()>, Box<dyn FaceSenderWrap>)>,
    next_id: u32,
}

impl<P : Platform> Faces<P> {
    fn next_handle(&mut self) -> FaceHandle {
        let id = self.next_id;
        self.next_id += 1;
        FaceHandle(id)
    }

    fn add_face<FS: FaceSender + 'static>(&mut self, handle: FaceHandle, task: <P as Platform>::Task<()>, sender: FS) {
        self.handles.push((handle, task, Box::new(FaceSenderWrapper { sender })));
        self.handles.sort_by(|a, b| a.0.cmp(&b.0));
    }

    fn remove_face(&mut self, face: FaceHandle) {
        if let Some(idx) = self.index_of_face(face) {
            let _ = self.handles.remove(idx);
        }
    }

    fn index_of_face(&self, face: FaceHandle) -> Option<usize> {
        if let Ok(idx) = self.handles.binary_search_by(|x| x.0.cmp(&face)) {
            return Some(idx)
        }
        None
    }

    async fn send_to(&mut self, face: FaceHandle, packet: &[u8]) -> Result<(), FaceError> {
        if let Some(idx) = self.index_of_face(face) {
            return self.handles[idx].2.send(packet).await
        }
        Err(FaceError::Disconnected)
    }
}



use core::pin::Pin;
trait FaceSenderWrap {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + 'a>>;
}

struct FaceSenderWrapper<FS> where  FS: FaceSender {
    sender: FS,
}

impl<FS> FaceSenderWrap for FaceSenderWrapper<FS> where  FS: FaceSender {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + 'a>> {
        Box::pin(self.sender.send(&bytes))
    }
}


const DEFAULT_DEADLINE_INCREMENT_MS : u64 = 4000; // 4 sec
const RETRANSMISSION_PERIOD_MS : u64 = 1000; // 1 sec


// It might be possible to implement this without Tasks when the async system matures
//  (so we do not need the spawn method in the platform and can be executor-agnostic).


/* 

use core::alloc::Layout;
use core::mem::ManuallyDrop;

/// A reusable `Pin<Box<dyn Future<Output = T> + Send + 'a>>`.
///
/// This type lets you replace the future stored in the box without
/// reallocating when the size and alignment permits this.
struct ReusableBoxFuture<'a, T> {
    boxed: Pin<Box<dyn Future<Output = T> + 'a>>,
}


/// [`Stream`]: trait@crate::Stream
struct BroadcastStream<'a, FR : FaceReceiver + 'a> {
    inner: ReusableBoxFuture<'a, (Result<&'a [u8], FaceError>, &'a FR)>,
}


async fn make_future<'a, FR : FaceReceiver + 'a>(rx: &'a FR) -> (Result<&'a [u8], FaceError>, &'a FR) {
    let result = rx.recv().await;
    (result, rx)
}

impl<'a, FR : FaceReceiver> BroadcastStream<'a, FR> {
    /// Create a new `BroadcastStream`.
    pub fn new(rx: &'a FR) -> Self {
        Self { 
            inner: ReusableBoxFuture::new(make_future(rx)),
        }
    }
}

impl<'a, FR : FaceReceiver> Stream for BroadcastStream<'a, FR> {
    type Item = Result<&'a [u8], FaceError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (result, rx) = core::task::ready!(self.inner.poll(cx));
        self.inner.set(make_future(rx));
        Poll::Ready(Some(result))
        
        /*match result {
            Ok(item) => Poll::Ready(Some(Ok(item))),
            Err(FaceError::Disconnected) => Poll::Ready(None),
        }*/
    }
}




impl<'a, T> ReusableBoxFuture<'a, T> {
    /// Create a new `ReusableBoxFuture<T>` containing the provided future.
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = T> + 'a,
    {
        Self {
            boxed: Box::pin(future),
        }
    }

    /// Replace the future currently stored in this box.
    ///
    /// This reallocates if and only if the layout of the provided future is
    /// different from the layout of the currently stored future.
    pub fn set<F>(&mut self, future: F)
    where
        F: Future<Output = T> + 'a,
    {
        if let Err(future) = self.try_set(future) {
            *self = Self::new(future);
        }
    }

    /// Replace the future currently stored in this box.
    ///
    /// This function never reallocates, but returns an error if the provided
    /// future has a different size or alignment from the currently stored
    /// future.
    pub fn try_set<F>(&mut self, future: F) -> Result<(), F>
    where
        F: Future<Output = T>  + 'a,
    {
        // If we try to inline the contents of this function, the type checker complains because
        // the bound `T: 'a` is not satisfied in the call to `pending()`. But by putting it in an
        // inner function that doesn't have `T` as a generic parameter, we implicitly get the bound
        // `F::Output: 'a` transitively through `F: 'a`, allowing us to call `pending()`.
        #[inline(always)]
        fn real_try_set<'a, F>(
            this: &mut ReusableBoxFuture<'a, F::Output>,
            future: F,
        ) -> Result<(), F>
        where
            F: Future + 'a,
        {
            // future::Pending<T> is a ZST so this never allocates.
            let boxed = core::mem::replace(&mut this.boxed, Box::pin(futures_lite::future::pending()));
            reuse_pin_box(boxed, future, |boxed| this.boxed = Pin::from(boxed))
        }

        real_try_set(self, future)
    }

    /// Get a pinned reference to the underlying future.
    pub fn get_pin(&mut self) -> Pin<&mut (dyn Future<Output = T>)> {
        self.boxed.as_mut()
    }

    /// Poll the future stored inside this box.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        self.get_pin().poll(cx)
    }
}

impl<T> Future for ReusableBoxFuture<'_, T> {
    type Output = T;

    /// Poll the future stored inside this box.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        Pin::into_inner(self).get_pin().poll(cx)
    }
}


fn reuse_pin_box<T: ?Sized, U, O, F>(boxed: Pin<Box<T>>, new_value: U, callback: F) -> Result<O, U>
where
    F: FnOnce(Box<U>) -> O,
{
    let layout = Layout::for_value::<T>(&*boxed);
    if layout != Layout::new::<U>() {
        return Err(new_value);
    }

    // SAFETY: We don't ever construct a non-pinned reference to the old `T` from now on, and we
    // always drop the `T`.
    let raw: *mut T = Box::into_raw(unsafe { Pin::into_inner_unchecked(boxed) });

    // When dropping the old value panics, we still want to call `callback` — so move the rest of
    // the code into a guard type.
    let guard = CallOnDrop::new(|| {
        let raw: *mut U = raw.cast::<U>();
        unsafe { raw.write(new_value) };

        // SAFETY:
        // - `T` and `U` have the same layout.
        // - `raw` comes from a `Box` that uses the same allocator as this one.
        // - `raw` points to a valid instance of `U` (we just wrote it in).
        let boxed = unsafe { Box::from_raw(raw) };

        callback(boxed)
    });

    // Drop the old value.
    unsafe { core::ptr::drop_in_place(raw) };

    // Run the rest of the code.
    Ok(guard.call())
}

struct CallOnDrop<O, F: FnOnce() -> O> {
    f: ManuallyDrop<F>,
}

impl<O, F: FnOnce() -> O> CallOnDrop<O, F> {
    fn new(f: F) -> Self {
        let f = ManuallyDrop::new(f);
        Self { f }
    }
    fn call(self) -> O {
        let mut this = ManuallyDrop::new(self);
        let f = unsafe { ManuallyDrop::take(&mut this.f) };
        f()
    }
}


impl<O, F: FnOnce() -> O> Drop for CallOnDrop<O, F> {
    fn drop(&mut self) {
        let f = unsafe { ManuallyDrop::take(&mut self.f) };
        f();
    }
}

/* 
// The only method called on self.boxed is poll, which takes &mut self, so this
// struct being Sync does not permit any invalid access to the Future, even if
// the future is not Sync.
unsafe impl<T> Sync for ReusableBoxFuture<'_, T> {}

impl<T> fmt::Debug for ReusableBoxFuture<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReusableBoxFuture").finish()
    }
}

*/



/* 
trait AttachedStream {
    type Item<'s> where Self: 's;

    fn poll_next<'s>(
        self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item<'s>>>;
}

struct FaceReceiverStream<FR> where FR: FaceReceiver + 'static {
    receiver: Box<FR>,

}

impl<FR: FaceReceiver + 'static> AttachedStream for FaceReceiverStream<FR> {
    type Item<'s> = Result<&'s [u8], FaceError>;

    fn poll_next<'s>(
        mut self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item<'s>>> {
        let recv = self.receiver.recv();
        let fut = core::pin::pin!(recv);
        match fut.poll(cx) {
            Poll::Ready(v) => Poll::Ready(Some(v)),
            Poll::Pending => Poll::Pending,
        }
    }
}
*/





use core::task::{Poll, Context};
use futures_lite::FutureExt;


/* 
struct FaceReceiverStream<'a, FR> where FR: FaceReceiver + 'static {
    receiver: Box<FR>,
    phantom_data: core::marker::PhantomData<&'a ()>,

}

impl<'a, FR: FaceReceiver + 'static> Stream for FaceReceiverStream<'a, FR> {
    type Item = Result<&'b [u8], FaceError> where Self : 'b;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let recv = self.receiver.recv();
        let fut = core::pin::pin!(recv);
        match fut.poll(cx) {
            Poll::Ready(v) => Poll::Ready(Some(v)),
            Poll::Pending => Poll::Pending,
        }
        
        /*match fut.poll(cx) {
            Poll::Ready(v) => Poll::Ready(Some(v)),
            Poll::Pending => Poll::Pending,
        }*/
        
        //Pin::new(&mut self.receiver).recv().poll(cx).map(move |x| Some(x))
    }
}


impl<'a, FR> From<FR> for FaceReceiverStream<'a, FR> where FR: FaceReceiver + 'a  {
    fn from(receiver: FR) -> Self {
        Self { receiver: Box::pin(receiver), phantom_data: Default::default() }
    }
}*/



/* 
use futures_lite::future::block_on;
trait FaceSenderWrap {
    fn send(&mut self, bytes: &[u8]) -> Result<(), FaceError>;
}

struct FaceSenderWrapper<FS> where  FS: FaceSender{
    sender: FS
}

impl<FS> FaceSenderWrap for FaceSenderWrapper<FS> where  FS: FaceSender {
    fn send(&mut self, bytes: &[u8]) -> Result<(), FaceError> {
        block_on(self.sender.send(bytes))
    }
}
*/

*/