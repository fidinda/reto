use std::thread::Thread;

use crate::{forwarder::FaceToken, platform::forwarder::FaceQueue};

pub struct SocketId(
    #[cfg(any(unix, target_os = "hermit"))] pub(crate) std::os::fd::OwnedFd,
    #[cfg(windows)] pub(crate) std::os::windows::io::OwnedSocket,
);

pub struct Waker {
    thread: Thread,
    face: FaceToken,
    queue: FaceQueue,
}

impl Waker {
    pub(crate) fn new(thread: Thread, face: FaceToken, queue: FaceQueue) -> Self {
        Self {
            thread,
            face,
            queue,
        }
    }

    pub fn notify(&self) {
        self.queue.enqueue(&[self.face]);
        self.thread.unpark();
    }
}

// This trait if for faces to implement notifications that they are ready.
// There are two ways they can do this that are used if available:
//  - Using the system's internal polling mechanisms for socket-based networking
//  - Using thread parking and waking
pub trait Notifying {
    fn socket_id(&self) -> Option<SocketId> {
        None
    }

    fn register_waker(&mut self, _waker: Waker) {}
}
