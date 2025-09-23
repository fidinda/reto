use alloc::rc::Rc;
use core::cell::RefCell;

use crate::face::{FaceError, FaceReceiver, FaceSender};

pub struct LocalSender<const SIZE: usize> {
    inner: Rc<RefCell<RingBuffer<SIZE>>>,
}
pub struct LocalReceiver<const SIZE: usize> {
    inner: Rc<RefCell<RingBuffer<SIZE>>>,
}

pub fn local_face<const SIZE: usize>() -> (LocalSender<SIZE>, LocalReceiver<SIZE>) {
    let inner = Rc::new(RefCell::new(RingBuffer::new()));

    let sender = LocalSender {
        inner: Rc::clone(&inner),
    };
    let receiver = LocalReceiver { inner };

    (sender, receiver)
}

impl<const SIZE: usize> FaceSender for LocalSender<SIZE> {
    fn try_send(&mut self, src: &[u8]) -> Result<usize, FaceError> {
        if Rc::strong_count(&self.inner) <= 1 {
            return Err(FaceError::Disconnected);
        }

        Ok(self.inner.borrow_mut().write(src))
    }
}

impl<const SIZE: usize> FaceReceiver for LocalReceiver<SIZE> {
    fn try_recv(&mut self, dst: &mut [u8]) -> Result<usize, FaceError> {
        let bytes_read = self.inner.borrow_mut().read(dst);

        // We only report the disconnect after draining the available bytes
        if bytes_read == 0 && Rc::strong_count(&self.inner) <= 1 {
            return Err(FaceError::Disconnected);
        }

        Ok(bytes_read)
    }
}

pub struct RingBuffer<const SIZE: usize> {
    storage: [u8; SIZE],
    read: usize,
    write: usize,
}

impl<const SIZE: usize> RingBuffer<SIZE> {
    pub fn new() -> Self {
        Self {
            storage: [0; SIZE],
            read: 0,
            write: 0,
        }
    }

    pub fn write(&mut self, src: &[u8]) -> usize {
        let src_len = src.len();
        if src_len == 0 {
            return 0;
        }

        let ring_len = self.storage.len();
        let mut bytes_written = 0;

        // We can fill in everything from the write head to the end unless the read head is at 0.
        //  If that is the case, we need to keep one element at the end free so write does not become 0.
        if self.write >= self.read {
            let read_at_zero = (self.read == 0) as usize;
            let tail_bytes = (ring_len - read_at_zero)
                .saturating_sub(self.write)
                .min(src_len);
            let offset = self.write;
            if tail_bytes > 0 {
                self.storage[offset..(offset + tail_bytes)].copy_from_slice(&src[..tail_bytes]);
                bytes_written += tail_bytes;
                self.write = (self.write + tail_bytes) % ring_len;
            }
        }

        // If there are still bytes remaining we can write up to (read - write - 1) bytes,
        //  so the write head is at most 1 less than the read head.
        if src_len > bytes_written && self.read.saturating_sub(self.write) > 1 {
            let head_bytes = self
                .read
                .saturating_sub(self.write + 1)
                .min(src_len - bytes_written);
            let offset = self.write;
            self.storage[offset..(offset + head_bytes)]
                .copy_from_slice(&src[bytes_written..(bytes_written + head_bytes)]);
            bytes_written += head_bytes;
            self.write += head_bytes;
        }

        bytes_written
    }

    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let dst_len = dst.len();
        if dst_len == 0 {
            return 0;
        }

        let ring_len = self.storage.len();
        let mut bytes_read = 0;

        // If the read head is after the write head we can always read all of the elements
        //  up until the end of the buffer.
        if self.read > self.write {
            let tail_bytes = (ring_len - self.read).min(dst_len);
            if tail_bytes > 0 {
                let offset = self.read;
                dst[..tail_bytes].copy_from_slice(&self.storage[offset..(offset + tail_bytes)]);
                bytes_read += tail_bytes;
                self.read = (self.read + tail_bytes) % ring_len;
            }
        }

        // If there still are bytes that can be put into dst, we can also read everything
        //  from the read head up to and including the write head (assuming read < write).
        if dst_len > bytes_read && self.read < self.write {
            let head_bytes = self
                .write
                .saturating_sub(self.read)
                .min(dst_len - bytes_read);
            let offset = self.read;
            dst[bytes_read..(bytes_read + head_bytes)]
                .copy_from_slice(&self.storage[offset..(offset + head_bytes)]);
            bytes_read += head_bytes;
            self.read += head_bytes;
        }

        bytes_read
    }
}

#[cfg(test)]
mod tests {
    use crate::face::{FaceReceiver, FaceSender};

    #[test]
    fn test_local() {
        let (mut sender, mut receiver) = super::local_face::<8>();

        let mut buffer = [0; 8];

        assert_eq!(receiver.try_recv(&mut buffer), Ok(0));

        assert_eq!(sender.try_send(&[]), Ok(0));
        assert_eq!(sender.try_send(&[12]), Ok(1));

        assert_eq!(receiver.try_recv(&mut []), Ok(0));
        assert_eq!(receiver.try_recv(&mut buffer[0..0]), Ok(0));
        assert_eq!(receiver.try_recv(&mut buffer), Ok(1));
        assert_eq!(buffer[0], 12);

        assert_eq!(receiver.try_recv(&mut buffer), Ok(0));

        assert_eq!(sender.try_send(&[1, 2, 3, 4, 5]), Ok(5));

        assert_eq!(sender.try_send(&[6, 7, 8, 9]), Ok(2));

        assert_eq!(receiver.try_recv(&mut buffer[0..2]), Ok(2));
        assert_eq!(receiver.try_recv(&mut buffer[2..]), Ok(5));
        assert_eq!(buffer[0..7], [1, 2, 3, 4, 5, 6, 7]);
    }
}
