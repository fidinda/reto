use ewebsock::{Options, WsEvent, WsMessage, WsReceiver, WsSender};

use crate::face::{FaceError, FaceReceiver, FaceSender};

pub struct WebSocketOptions {}

pub struct WebSocketSender {
    sender: WsSender,
}

pub struct WebSocketReceiver {
    receiver: WsReceiver,
    pending: Vec<u8>,
}

impl FaceSender for WebSocketSender {
    fn try_send(&mut self, src: &[u8]) -> Result<usize, FaceError> {
        // TODO: avoid creating a vec here if possible
        self.sender.send(WsMessage::Binary(src.to_vec()));
        Ok(src.len())
    }
}

impl FaceReceiver for WebSocketReceiver {
    fn try_recv(&mut self, dst: &mut [u8]) -> Result<usize, FaceError> {
        let mut bytes_received = 0;
        if self.pending.len() > 0 {
            bytes_received = self.pending.len().min(dst.len());
            dst[0..bytes_received].copy_from_slice(&self.pending[0..bytes_received]);

            if bytes_received < self.pending.len() {
                self.pending.drain(0..bytes_received);
            } else {
                self.pending.clear();
            }
        }

        let bytes_available = dst.len() - bytes_received;

        if bytes_available > 0 {
            loop {
                match self.receiver.try_recv() {
                    Some(WsEvent::Message(WsMessage::Binary(b))) => {
                        let bytes_to_copy = bytes_available.min(b.len());
                        dst[bytes_received..(bytes_received + bytes_to_copy)]
                            .copy_from_slice(&b[..bytes_to_copy]);
                        if bytes_to_copy < b.len() {
                            self.pending.extend_from_slice(&b[bytes_to_copy..]);
                        }
                    }
                    Some(_) => continue, // Ignore all non-binary messages
                    _ => break,
                }
            }
        }

        Ok(bytes_received)
    }
}

pub fn web_socket_face_with_wake_up(
    url: &str,
    options: WebSocketOptions,
    wake_up: impl Fn() + Send + Sync + 'static,
) -> Result<(WebSocketSender, WebSocketReceiver), String> {
    let options = options.into();
    let (sender, receiver) = ewebsock::connect_with_wakeup(url, options, wake_up)?;
    Ok((
        WebSocketSender { sender },
        WebSocketReceiver {
            receiver,
            pending: Vec::new(),
        },
    ))
}

impl From<WebSocketOptions> for Options {
    fn from(_value: WebSocketOptions) -> Self {
        Options::default()
    }
}
