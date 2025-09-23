use std::{
    io::{Error, ErrorKind, Read, Write},
    os::unix::net::{UnixDatagram, UnixStream},
};

use crate::platform::native::notifying::Notifying;
use crate::{
    face::{FaceError, FaceReceiver, FaceSender},
    forwarder::MAX_PACKET_SIZE,
};

use super::notifying::SocketId;
#[cfg(any(unix, target_os = "hermit"))]
use super::notifying::Waker;

pub struct UnixDatagramSender {
    socket: UnixDatagram,
    buffer: Vec<u8>,
}

pub struct UnixDatagramReceiver {
    socket: UnixDatagram,
}

impl FaceSender for UnixDatagramSender {
    fn try_send(&mut self, src: &[u8]) -> Result<usize, FaceError> {
        self.buffer.extend_from_slice(src);
        Ok(src.len())
    }

    fn flush(&mut self) -> Result<(), FaceError> {
        match self.socket.send(&self.buffer) {
            Ok(bytes_sent) => {
                self.buffer.drain(..bytes_sent);
                Ok(())
            }
            Err(io_err) => match io_err.kind() {
                ErrorKind::WouldBlock => Ok(()),
                _ => Err(FaceError::Disconnected),
            },
        }
    }
}

impl FaceReceiver for UnixDatagramReceiver {
    fn try_recv(&mut self, dst: &mut [u8]) -> Result<usize, FaceError> {
        match self.socket.recv(dst) {
            Ok(bytes_received) => Ok(bytes_received),
            Err(io_err) => match io_err.kind() {
                ErrorKind::WouldBlock => Ok(0),
                _ => Err(FaceError::Disconnected),
            },
        }
    }
}

#[cfg(any(unix, target_os = "hermit"))]
impl Notifying for UnixDatagramReceiver {
    fn socket_id(&self) -> Option<SocketId> {
        use std::os::fd::AsFd;
        Some(SocketId(self.socket.as_fd().try_clone_to_owned().ok()?))
    }

    fn register_waker(&mut self, _waker: Waker) {}
}

#[cfg(target_os = "windows")]
impl Notifying for UnixDatagramReceiver {
    fn socket_id(&self) -> Option<SocketId> {
        use std::os::fd::AsHandle;
        Some(SocketId(self.socket.as_handle().try_clone_to_owned().ok()?))
    }
}

pub fn unix_datagram_face(
    socket: UnixDatagram,
) -> Result<(UnixDatagramSender, UnixDatagramReceiver), Error> {
    socket.set_nonblocking(true)?;
    let sender = UnixDatagramSender {
        socket: socket.try_clone()?,
        buffer: Vec::with_capacity(MAX_PACKET_SIZE),
    };
    let receiver = UnixDatagramReceiver { socket };
    Ok((sender, receiver))
}

pub struct UnixStreamSender {
    stream: UnixStream,
}

pub struct UnixStreamReceiver {
    stream: UnixStream,
}

impl FaceSender for UnixStreamSender {
    fn try_send(&mut self, src: &[u8]) -> Result<usize, FaceError> {
        match self.stream.write(src) {
            Ok(bytes_sent) => Ok(bytes_sent),
            Err(io_err) => match io_err.kind() {
                ErrorKind::WouldBlock => Ok(0),
                _ => Err(FaceError::Disconnected),
            },
        }
    }
}

impl FaceReceiver for UnixStreamReceiver {
    fn try_recv(&mut self, dst: &mut [u8]) -> Result<usize, FaceError> {
        match self.stream.read(dst) {
            Ok(bytes_received) => Ok(bytes_received),
            Err(io_err) => match io_err.kind() {
                ErrorKind::WouldBlock => Ok(0),
                _ => Err(FaceError::Disconnected),
            },
        }
    }
}

#[cfg(any(unix, target_os = "hermit"))]
impl Notifying for UnixStreamReceiver {
    fn socket_id(&self) -> Option<SocketId> {
        use std::os::fd::AsFd;
        Some(SocketId(self.stream.as_fd().try_clone_to_owned().ok()?))
    }

    fn register_waker(&mut self, _waker: Waker) {}
}

#[cfg(target_os = "windows")]
impl Notifying for UnixStreamReceiver {
    fn socket_id(&self) -> Option<SocketId> {
        use std::os::fd::AsHandle;
        Some(SocketId(self.stream.as_handle().try_clone_to_owned().ok()?))
    }
}

pub fn unix_stream_face(
    stream: UnixStream,
) -> Result<(UnixStreamSender, UnixStreamReceiver), Error> {
    stream.set_nonblocking(true)?;
    let sender = UnixStreamSender {
        stream: stream.try_clone()?,
    };
    let receiver = UnixStreamReceiver { stream };
    Ok((sender, receiver))
}
