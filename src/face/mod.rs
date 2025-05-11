mod datagram_face;
pub use datagram_face::*;

use core::future::Future;

// The Face abstracts away the underlying data transfer protocols.

// It deals with complete NDN packets (Interests and Data) and if
//  the underlying links have limited datagram size the Face itself
//  should handle fragmentation and reassembly.

// It is split into a sender and a recever halves such taht we can
//  drive them separately inside the forwarder.
// Conceptually they still jointly refer to the same interface.

pub enum FaceError {
    Disconnected,
}

pub trait FaceSender {
    fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), FaceError>>;
}

pub trait FaceReceiver {
    fn recv(&mut self) -> impl Future<Output = Result<&[u8], FaceError>>;
}
