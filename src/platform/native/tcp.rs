use std::{
    io::{Error, ErrorKind, Read, Write},
    net::TcpStream,
};

use crate::face::{FaceError, FaceReceiver, FaceSender};
use crate::platform::native::notifying::Notifying;

use super::notifying::SocketId;
#[cfg(any(unix, target_os = "hermit"))]
use super::notifying::Waker;

pub struct TcpSender {
    stream: TcpStream,
}

pub struct TcpReceiver {
    stream: TcpStream,
}

impl FaceSender for TcpSender {
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

impl FaceReceiver for TcpReceiver {
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
impl Notifying for TcpReceiver {
    fn socket_id(&self) -> Option<SocketId> {
        use std::os::fd::AsFd;
        Some(SocketId(self.stream.as_fd().try_clone_to_owned().ok()?))
    }

    fn register_waker(&mut self, _waker: Waker) {}
}

#[cfg(target_os = "windows")]
impl Notifying for TcpReceiver {
    fn socket_id(&self) -> Option<SocketId> {
        use std::os::windows::io::AsSocket;
        Some(SocketId(self.stream.as_socket().try_clone_to_owned().ok()?))
    }
}

pub fn tcp_face(stream: TcpStream) -> Result<(TcpSender, TcpReceiver), Error> {
    stream.set_nonblocking(true)?;
    let sender = TcpSender {
        stream: stream.try_clone()?,
    };
    let receiver = TcpReceiver { stream };
    Ok((sender, receiver))
}
