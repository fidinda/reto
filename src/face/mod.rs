mod datagram_face;
pub use datagram_face::*;

use core::future::Future;

// The Face abstracts away the underlying data transfer protocols.

// It operates using raw bytes and can arbitrarily fragment the data
//  to satisfy the underlying networking mechanism.

// It is split into a sender and a recever halves such that we can
//  drive them separately inside the forwarder.
// Conceptually they still jointly refer to the same interface.

pub enum FaceError {
    Disconnected,
}

pub trait FaceSender {
    fn send(&mut self, src: &[u8]) -> impl Future<Output = Result<usize, FaceError>>;
}

pub trait FaceReceiver {
    fn recv(&mut self, dst: &mut [u8]) -> impl Future<Output = Result<usize, FaceError>>;
}
