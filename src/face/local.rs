use core::cell::RefCell;
use alloc::rc::Rc;

use crate::face::{ringbuffer::RingBuffer, FaceError, FaceReceiver, FaceSender};

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
