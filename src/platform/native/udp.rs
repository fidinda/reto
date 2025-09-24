use core::net::IpAddr;
use std::{
    io::{Error, ErrorKind},
    net::UdpSocket,
};

use crate::platform::native::notifying::Notifying;
use crate::{
    face::{FaceError, FaceReceiver, FaceSender},
    forwarder::MAX_PACKET_SIZE,
};

use super::notifying::SocketId;
#[cfg(any(unix, target_os = "hermit"))]
use super::notifying::Waker;

pub struct UdpSender {
    socket: UdpSocket,
    buffer: Vec<u8>,
    addr: (IpAddr, u16)
}

pub struct UdpReceiver {
    socket: UdpSocket,
}

impl FaceSender for UdpSender {
    fn try_send(&mut self, src: &[u8]) -> Result<usize, FaceError> {
        self.buffer.extend_from_slice(src);
        Ok(src.len())
    }

    fn flush(&mut self) -> Result<(), FaceError> {
        match self.socket.send_to(&self.buffer, self.addr) {
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

impl FaceReceiver for UdpReceiver {
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
impl Notifying for UdpReceiver {
    fn socket_id(&self) -> Option<SocketId> {
        use std::os::fd::AsFd;
        Some(SocketId(self.socket.as_fd().try_clone_to_owned().ok()?))
    }

    fn register_waker(&mut self, _waker: Waker) {}
}

#[cfg(target_os = "windows")]
impl Notifying for UdpReceiver {
    fn socket_id(&self) -> Option<SocketId> {
        use std::os::fd::AsHandle;
        Some(SocketId(self.socket.as_handle().try_clone_to_owned().ok()?))
    }
}

pub fn udp_face(socket: UdpSocket, remote_address: impl Into<IpAddr>, remote_port: u16) -> Result<(UdpSender, UdpReceiver), Error> {
    socket.set_nonblocking(true)?;
    let sender = UdpSender {
        socket: socket.try_clone()?,
        buffer: Vec::with_capacity(MAX_PACKET_SIZE),
        addr: (remote_address.into(), remote_port),
    };
    let receiver = UdpReceiver { socket };
    Ok((sender, receiver))
}
