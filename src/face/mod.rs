mod datagram_face;

pub enum FaceError {
    Disconnected,
}

pub trait FaceSender {
    // This lets us send bytes to the face.
    // It returns the number of bytes sent on success or a FaceError.
    // It can return 0 if the face is not ready to send right now.
    fn send(&mut self, src: &[u8]) -> Result<usize, FaceError>;
}

pub trait FaceReceiver {
    // We try to receive the bytes from the face if any are available.
    // It returns the number of bytes received on success or a FaceError.
    // If the face has no bytes ready it returns
    fn try_recv(&mut self, dst: &mut [u8]) -> Result<usize, FaceError>;
}
