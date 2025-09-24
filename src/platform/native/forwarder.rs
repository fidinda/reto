use core::{marker::PhantomData, time::Duration};

use std::{
    collections::VecDeque,
    sync::{
        mpsc::{Sender, TryRecvError},
        Arc, Mutex,
    },
    thread::Thread,
    time::Instant,
};

use crate::{
    clock::Clock,
    face::{FaceReceiver, FaceSender},
    forwarder::{FaceToken, Forwarder, ForwarderError, ForwarderMetrics},
    hash::{Hasher, Sha256Digest},
    name::Name,
    platform::native::notifying::{Notifying, SocketId, Waker},
    tables::Tables,
};

pub struct BlockingForwarder<C, H, M, T>
where
    C: Clock,
    H: Hasher<Digest = Sha256Digest>,
    M: ForwarderMetrics,
    T: Tables,
{
    forwarder: Forwarder<C, H, M, T>,
    local_queue: VecDeque<FaceToken>,
    shared_queue: FaceQueue,
    forwarding_thread: Thread,
    poller_sender: Sender<PollerMessage>,
    _marker: PhantomData<*const ()>, // !Send
}

impl<C, H, M, T> BlockingForwarder<C, H, M, T>
where
    C: Clock,
    H: Hasher<Digest = Sha256Digest>,
    M: ForwarderMetrics,
    T: Tables,
{
    pub fn new(clock: C, hasher: H, metrics: M, tables: T) -> Self {
        let forwarder = Forwarder::new(clock, hasher, metrics, tables);
        let shared_queue = FaceQueue::new();
        let poller_queue = shared_queue.clone();
        let forwarding_thread = std::thread::current();
        let wakeup_thread = forwarding_thread.clone();
        let (poller_sender, poller_receiver) = std::sync::mpsc::channel();

        // We spin up another thread on which we listen to socket events and notify the queue
        std::thread::spawn(move || {
            let mut latest_faces = Vec::with_capacity(32);
            let mut poller = match poller::ReadPoller::new() {
                Ok(poller) => poller,
                Err(_) => return,
            };

            // This is the timeout that we wait while polling
            //  (and the latency with which we process register/unregister messages)
            let timeout = Some(Duration::from_millis(10));

            'poll: loop {
                'recv: loop {
                    match poller_receiver.try_recv() {
                        Ok(msg) => match msg {
                            PollerMessage::Register { face, socket } => {
                                poller.register(face, socket)
                            }
                            PollerMessage::Unregister { face } => poller.unregister(face),
                        },
                        Err(TryRecvError::Disconnected) => break 'poll, // Disconnected, so we exit
                        Err(TryRecvError::Empty) => break 'recv, // Empty, so we do the polling
                    }
                }

                latest_faces.clear();
                poller.wait(&mut latest_faces, timeout);

                if latest_faces.len() > 0 {
                    poller_queue.enqueue(&latest_faces);
                    wakeup_thread.unpark();
                }
            }
        });

        Self {
            forwarder,
            local_queue: VecDeque::default(),
            shared_queue,
            forwarding_thread,
            poller_sender,
            _marker: PhantomData::default(),
        }
    }

    pub fn add_face<FS, FR>(&mut self, sender: FS, mut receiver: FR) -> Option<FaceToken>
    where
        FS: FaceSender + 'static,
        FR: FaceReceiver + Notifying + 'static,
    {
        let face = self.forwarder.next_face_token()?;

        // Want to register with poller, if this is a socket
        if let Some(socket) = receiver.socket_id() {
            let _ = self
                .poller_sender
                .send(PollerMessage::Register { face, socket });
        }

        // Also register a waker, whcih will usually be a noop for socket faces
        let waker = Waker::new(
            self.forwarding_thread.clone(),
            face,
            self.shared_queue.clone(),
        );
        receiver.register_waker(waker);

        match self.forwarder.add_face(sender, receiver) {
            Some(token) => assert!(token == face),
            None => todo!(), // TODO: handle error here
        }

        Some(face)
    }

    pub fn remove_face(&mut self, token: FaceToken) -> bool {
        let _ = self
            .poller_sender
            .send(PollerMessage::Unregister { face: token });
        self.forwarder.remove_face(token)
    }

    pub fn register_name_prefix_for_forwarding<'a>(
        &mut self,
        name_prefix: Name<'a>,
        forward_to: FaceToken,
        cost: u32,
    ) {
        self.forwarder
            .register_name_prefix_for_forwarding(name_prefix, forward_to, cost)
    }

    pub fn unregister_name_prefix_for_forwarding<'a>(
        &mut self,
        name_prefix: Name<'a>,
        forward_to: FaceToken,
    ) -> bool {
        self.forwarder
            .unregister_name_prefix_for_forwarding(name_prefix, forward_to)
    }

    pub fn forward(&mut self, timeout: Option<Duration>) -> Result<FaceToken, ForwarderError> {
        let deadline = timeout.map(|t| Instant::now() + t);

        loop {
            // First we try to forward on all the faces that we already have in the local queue
            while let Some(face) = self.local_queue.pop_front() {
                match self.forwarder.try_forward_from_face(face) {
                    Ok(_) => return Ok(face),
                    Err(ForwarderError::NothingToForward) => {}
                    Err(err) => return Err(err),
                }
            }

            // Then we try to forward on any face in the forwarder, including the non-notifying
            match self.forwarder.try_forward_from_any_face() {
                Ok(face) => return Ok(face),
                Err(ForwarderError::NothingToForward) => {}
                Err(err) => return Err(err),
            }

            // Finally, we get the new notifications from the shared queue
            match self.shared_queue.queue.lock() {
                Ok(mut q) => {
                    if q.len() > 0 {
                        std::mem::swap(&mut *q, &mut self.local_queue);
                    }
                }
                Err(_) => panic!(), // TODO: maybe a better way here?
            }

            // If there now are events in the local queue we repeat the loop to forward on them
            if self.local_queue.len() > 0 {
                continue;
            }

            // If we are here, there are no pending faces to poll and we need to wait
            //  until we get a new notification or until the deadline
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    // If we are past the deadline, we return empty
                    return Err(ForwarderError::NothingToForward);
                } else {
                    // Otherwise we part the thread hoping for a waker to wake us up
                    std::thread::park_timeout(deadline - now);
                }
            } else {
                std::thread::park();
            }
        }
    }
}

pub(crate) struct FaceQueue {
    queue: Arc<Mutex<VecDeque<FaceToken>>>,
}

impl FaceQueue {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn enqueue(&self, faces: &[FaceToken]) {
        match self.queue.lock() {
            Ok(mut q) => q.extend(faces),
            Err(_) => {}
        }
    }
}

impl Clone for FaceQueue {
    fn clone(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
        }
    }
}

enum PollerMessage {
    Register { face: FaceToken, socket: SocketId },
    Unregister { face: FaceToken },
}

#[cfg(all(
    feature = "poller",
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_os = "illumos",
        target_os = "solaris",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "vxworks",
        target_os = "hermit",
        target_os = "fuchsia",
        target_os = "horizon",
        target_os = "windows"
    )
))]
mod poller {
    use polling::{Event, PollMode};

    use crate::{forwarder::FaceToken, platform::native::notifying::SocketId};

    pub(crate) struct ReadPoller {
        faces: Vec<(FaceToken, SocketId)>,
        socket_poller: polling::Poller,
        socket_events: polling::Events,
        should_re_add: bool,
    }

    impl ReadPoller {
        pub(crate) fn new() -> Result<Self, std::io::Error> {
            let socket_poller = polling::Poller::new()?;
            let should_re_add = !socket_poller.supports_level();
            Ok(Self {
                faces: Vec::new(),
                socket_poller,
                socket_events: polling::Events::new(),
                should_re_add,
            })
        }

        pub(crate) fn register(&mut self, face: FaceToken, socket: SocketId) {
            let idx = match self.find_face(face) {
                Ok(idx) => {
                    let mut old = socket;
                    std::mem::swap(&mut old, &mut self.faces[idx].1);
                    // TODO: what happens if this is one of our other sockets?
                    let _ = self.socket_poller.delete(old.source());
                    idx
                }
                Err(idx) => {
                    self.faces.insert(idx, (face, socket));
                    idx
                }
            };

            // We promise to delete all the file descriptors from the poller
            //  which we do in ReadPoller::drop() and when replacing the socuekts above.
            unsafe {
                let mode = if self.should_re_add {
                    PollMode::Oneshot
                } else {
                    PollMode::Level
                };

                let _ = self.socket_poller.add_with_mode(
                    self.faces[idx].1.raw_source(),
                    Event::readable(face.0 as usize),
                    mode,
                );
            }
        }

        pub(crate) fn unregister(&mut self, face: FaceToken) {
            match self.find_face(face) {
                Ok(idx) => {
                    let old = self.faces.remove(idx).1;
                    let _ = self.socket_poller.delete(old.source());
                }
                Err(_) => {}
            }
        }

        pub(crate) fn wait(
            &mut self,
            faces: &mut Vec<FaceToken>,
            timeout: Option<core::time::Duration>,
        ) {
            self.socket_events.clear();

            let new_count = match self.socket_poller.wait(&mut self.socket_events, timeout) {
                Ok(new_count) => new_count,
                Err(_) => return,
            };

            debug_assert!(self.socket_events.len() == new_count);

            for ee in self.socket_events.iter() {
                if ee.readable {
                    let face = FaceToken(ee.key as u32);
                    faces.push(face);

                    if self.should_re_add {
                        if let Ok(idx) = self.find_face(face) {
                            let _ = self
                                .socket_poller
                                .modify(self.faces[idx].1.source(), Event::readable(ee.key));
                        }
                    }
                }
            }
        }

        fn find_face(&self, face: FaceToken) -> Result<usize, usize> {
            self.faces.binary_search_by(|(f, _)| f.cmp(&face))
        }
    }

    impl Drop for ReadPoller {
        fn drop(&mut self) {
            for (_face, socket) in self.faces.drain(..) {
                let _ = self.socket_poller.delete(socket.source());
            }
        }
    }

    #[cfg(any(unix, target_os = "hermit"))]
    use std::os::fd::{BorrowedFd, RawFd};

    #[cfg(any(unix, target_os = "hermit"))]
    impl SocketId {
        fn raw_source(&self) -> RawFd {
            use std::os::fd::AsRawFd;
            self.0.as_raw_fd()
        }

        fn source(&self) -> BorrowedFd<'_> {
            use std::os::fd::AsFd;
            self.0.as_fd()
        }
    }

    #[cfg(target_os = "windows")]
    use std::os::windows::io::{BorrowedSocket, RawSocket};

    #[cfg(target_os = "windows")]
    impl SocketId {
        fn raw_source(&self) -> RawSocket {
            use std::os::windows::io::AsRawSocket;
            self.0.as_raw_socket()
        }

        fn source(&self) -> BorrowedSocket<'_> {
            use std::os::windows::io::AsSocket;
            self.0.as_socket()
        }
    }
}

#[cfg(not(all(
    feature = "poller",
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        target_os = "illumos",
        target_os = "solaris",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "vxworks",
        target_os = "hermit",
        target_os = "fuchsia",
        target_os = "horizon",
        target_os = "windows"
    )
)))]
mod poller {
    use crate::{face::native::notifying::SocketId, forwarder::FaceToken};

    pub(crate) struct ReadPoller {}

    impl ReadPoller {
        pub(crate) fn new() -> Result<Self, std::io::Error> {
            Self {}
        }

        pub(crate) fn register(&mut self, face: FaceToken, socket: SocketId) {}

        pub(crate) fn unregister(&mut self, face: FaceToken) {}

        pub(crate) fn wait(
            &mut self,
            faces: &mut Vec<FaceToken>,
            timeout: Option<core::time::Duration>,
        ) {
        }
    }
}
