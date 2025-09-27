use crate::{
    face::{FaceError, FaceReceiver},
    forwarder::MAX_PACKET_SIZE,
    io::Decode,
    tlv::{TlvDecodingError, VarintDecodingError, TLV},
};

pub enum BufferedRecvError {
    NothingReceived,
    TlvTooBig(usize),
    DecodingError(TlvDecodingError),
    FaceError(FaceError),
}

pub trait BufferedFaceReceiver {
    fn try_recv(&mut self) -> Result<TLV<'_>, BufferedRecvError>;
}

pub struct BufferedReceiver<FR: FaceReceiver, const CAPACITY: usize = MAX_PACKET_SIZE> {
    receiver: FR,
    receiver_buffer: [u8; CAPACITY],
    receiver_buffer_cursor: usize,
    pending_receiver_buffer_change: usize,
}

impl<FR: FaceReceiver, const CAPACITY: usize> BufferedReceiver<FR, CAPACITY> {
    pub fn new(receiver: FR) -> Self {
        Self {
            receiver,
            receiver_buffer: [0; CAPACITY],
            receiver_buffer_cursor: 0,
            pending_receiver_buffer_change: 0,
        }
    }
}

pub fn default_buffered_receiver<FR: FaceReceiver>(receiver: FR) -> BufferedReceiver<FR> {
    BufferedReceiver::new(receiver)
}

impl<FR: FaceReceiver, const CAPACITY: usize> BufferedFaceReceiver
    for BufferedReceiver<FR, CAPACITY>
{
    fn try_recv(&mut self) -> Result<TLV<'_>, BufferedRecvError> {
        // Reset the cursor back by the size of the last processed element, if any
        // Doing it here and not in the end so we can return the TLV in a simle way
        if self.pending_receiver_buffer_change > 0 {
            if self.pending_receiver_buffer_change < self.receiver_buffer_cursor {
                // There are still some unprocessed bytes
                self.receiver_buffer.copy_within(
                    self.pending_receiver_buffer_change..self.receiver_buffer_cursor,
                    0,
                );
                self.receiver_buffer_cursor -= self.pending_receiver_buffer_change;
            } else {
                // We are done with this bunch of bytes
                self.receiver_buffer_cursor = 0;
            }
            self.pending_receiver_buffer_change = 0;
        }

        // We try to get some data from the face, if available
        match self
            .receiver
            .try_recv(&mut self.receiver_buffer[self.receiver_buffer_cursor..])
        {
            Ok(received) => self.receiver_buffer_cursor += received,
            Err(err) => return Err(BufferedRecvError::FaceError(err)),
        }

        // Try to parse the TLV in the beginning of the buffer
        let (tlv, tlv_len) =
            match TLV::try_decode(&self.receiver_buffer[0..self.receiver_buffer_cursor]) {
                Ok((tlv, tlv_len)) => (tlv, tlv_len),
                // If we have too few bytes this could be solved with a recv
                Err(TlvDecodingError::CannotDecodeType {
                    err: VarintDecodingError::BufferTooShort,
                }) => return Err(BufferedRecvError::NothingReceived),
                Err(TlvDecodingError::CannotDecodeLength {
                    err: VarintDecodingError::BufferTooShort,
                    ..
                }) => return Err(BufferedRecvError::NothingReceived),
                Err(TlvDecodingError::CannotDecodeValue { len, .. }) => {
                    if len > CAPACITY {
                        return Err(BufferedRecvError::TlvTooBig(len));
                    }
                    return Err(BufferedRecvError::NothingReceived);
                }
                Err(err) => return Err(BufferedRecvError::DecodingError(err)),
            };

        // If we are here, we could return the full TLV
        //  and so will want to remove these bytes before the next iteration
        self.pending_receiver_buffer_change = tlv_len;

        Ok(tlv)
    }
}
