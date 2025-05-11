use core::future::Future;

use crate::{FaceError, FaceReceiver, FaceSender};

// Implements the NDNLPv2 protocol over an underlying
//  datagram-based face with MTU

pub struct DatagramSender<S: FaceSender, const MTU: usize> {
    _sender: S,
    _buf: [u8; MTU],
}

impl<S: FaceSender, const MTU: usize> FaceSender for DatagramSender<S, MTU> {
    fn send(&mut self, _bytes: &[u8]) -> impl Future<Output = Result<(), FaceError>> {
        async { todo!() }
    }
}

pub struct DatagramReceiver<R: FaceReceiver, const MTU: usize> {
    // Bytes with MTU, etc.
    _receiver: R,
    _buf: [u8; MTU],
}

impl<R: FaceReceiver, const MTU: usize> FaceReceiver for DatagramReceiver<R, MTU> {
    fn recv(&mut self) -> impl Future<Output = Result<&[u8], FaceError>> {
        async { todo!() }
    }
}
