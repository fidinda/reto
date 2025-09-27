use core::time::Duration;

pub mod buffered;

pub mod local;

#[derive(Debug, PartialEq, Eq)]
pub enum FaceError {
    Disconnected,
}

pub trait FaceReceiver {
    // We try to receive the bytes from the face if any are available.
    // It returns the number of bytes received on success or a FaceError.
    // If the face has no bytes ready it returns 0.
    fn try_recv(&mut self, dst: &mut [u8]) -> Result<usize, FaceError>;
}

pub trait FaceSender {
    // This lets us send bytes to the face.
    // It returns the number of bytes sent on success or a FaceError.
    // It can return 0 if the face is not ready to send right now.
    fn try_send(&mut self, src: &[u8]) -> Result<usize, FaceError>;

    // Used to signal that a chunk of data can be sent further on.
    // Useful, for example, for datagram faces, which could buffer the
    //  changes and send the actual datagram when flush is called.
    fn flush(&mut self) -> Result<(), FaceError> {
        Ok(())
    }
}

pub trait BlockingFaceReceiver {
    fn recv(&mut self, dst: &mut [u8], timeout: Option<Duration>) -> Result<usize, FaceError>;
}

pub trait BlockingFaceSender {
    fn send(&mut self, src: &[u8], timeout: Option<Duration>) -> Result<usize, FaceError>;
}

impl<FS: FaceSender + ?Sized> crate::io::Write for FS {
    type Error = FaceError;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let len = bytes.len();
        let mut sent_so_far = 0;
        while sent_so_far < len {
            sent_so_far += self.try_send(&bytes[sent_so_far..])?;
        }
        debug_assert!(sent_so_far == len);
        Ok(())
    }
}
