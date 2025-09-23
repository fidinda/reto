use core::num::NonZeroUsize;
use std::sync::{Arc, Condvar, Mutex};

use crate::{
    face::{ringbuffer::RingBuffer, FaceError, FaceReceiver, FaceSender},
    platform::native::notifying::{Notifying, Waker},
};

pub struct SharedSender<const SIZE: usize> {
    inner: Arc<Shared<SIZE>>,
}
pub struct SharedReceiver<const SIZE: usize> {
    inner: Arc<Shared<SIZE>>,
}

pub fn shared_face<const SIZE: usize>() -> (SharedSender<SIZE>, SharedReceiver<SIZE>) {
    let inner = Arc::new(Shared {
        ring: Mutex::new((RingBuffer::new(), None)),
        available: Condvar::new(),
    });

    let sender = SharedSender {
        inner: Arc::clone(&inner),
    };
    let receiver = SharedReceiver { inner };

    (sender, receiver)
}

impl<const SIZE: usize> SharedReceiver<SIZE> {
    pub fn recv(&mut self, dst: &mut [u8]) -> Result<NonZeroUsize, FaceError> {
        let mut ring = self
            .inner
            .ring
            .lock()
            .map_err(|_| FaceError::Disconnected)?;

        loop {
            let read_bytes = ring.0.read(dst);
            match NonZeroUsize::new(read_bytes) {
                Some(read) => return Ok(read),
                None => {
                    ring = self
                        .inner
                        .available
                        .wait(ring)
                        .map_err(|_| FaceError::Disconnected)?
                }
            }
        }
    }
}

impl<const SIZE: usize> FaceSender for SharedSender<SIZE> {
    fn try_send(&mut self, src: &[u8]) -> Result<usize, FaceError> {
        if Arc::strong_count(&self.inner) <= 1 {
            return Err(FaceError::Disconnected);
        }

        let bytes_written = {
            let mut g = self
                .inner
                .ring
                .lock()
                .map_err(|_| FaceError::Disconnected)?;

            let bytes_written = g.0.write(src);

            if let Some(waker) = &g.1 {
                if bytes_written > 0 {
                    waker.notify();
                }
            }
            bytes_written
        };

        if bytes_written > 0 {
            self.inner.available.notify_one();
        }

        Ok(bytes_written)
    }
}

impl<const SIZE: usize> Drop for SharedSender<SIZE> {
    fn drop(&mut self) {
        self.inner.available.notify_one();
    }
}

impl<const SIZE: usize> FaceReceiver for SharedReceiver<SIZE> {
    fn try_recv(&mut self, dst: &mut [u8]) -> Result<usize, FaceError> {
        let bytes_read = self
            .inner
            .ring
            .lock()
            .map_err(|_| FaceError::Disconnected)?
            .0
            .read(dst);

        // We only report the disconnect after draining the available bytes
        if bytes_read == 0 && Arc::strong_count(&self.inner) <= 1 {
            return Err(FaceError::Disconnected);
        }

        Ok(bytes_read)
    }
}

impl<const SIZE: usize> Notifying for SharedReceiver<SIZE> {
    fn register_waker(&mut self, waker: Waker) {
        match self.inner.ring.lock() {
            Ok(mut g) => g.1 = Some(waker),
            Err(_) => {}
        }
    }
}

struct Shared<const SIZE: usize> {
    ring: Mutex<(RingBuffer<SIZE>, Option<Waker>)>,
    available: Condvar,
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::thread::sleep;

    use crate::face::{FaceError, FaceReceiver, FaceSender};

    #[test]
    fn test_same_thread() {
        let (mut sender, mut receiver) = super::shared_face::<8>();

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

    #[test]
    fn test_multi_thread() {
        let (mut sender, mut receiver) = super::shared_face::<8>();

        std::thread::spawn(move || {
            assert_eq!(sender.try_send(&[1, 2, 3, 4, 5]), Ok(5));
            assert_eq!(sender.try_send(&[6, 7, 8, 9]), Ok(2));
        });

        let mut buffer = [0; 8];
        let mut received = 0;
        while received < 7 {
            match receiver.try_recv(&mut buffer[received..]) {
                Ok(rec) => received += rec,
                Err(_) => panic!(),
            }
        }

        assert_eq!(buffer[0..7], [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_multi_thread_delay() {
        let (mut sender, mut receiver) = super::shared_face::<8>();

        std::thread::spawn(move || {
            assert_eq!(sender.try_send(&[1, 2, 3, 4, 5]), Ok(5));
            assert_eq!(sender.try_send(&[6, 7, 8, 9]), Ok(2));
        });

        sleep(Duration::from_secs(1));

        let mut buffer = [0; 8];
        let mut received = 0;
        while received < 7 {
            match receiver.try_recv(&mut buffer[received..]) {
                Ok(rec) => received += rec,
                Err(_) => panic!(),
            }
        }

        assert_eq!(buffer[0..7], [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_multi_thread_big() {
        let (mut sender, mut receiver) = super::shared_face::<10240>();

        std::thread::spawn(move || {
            assert_eq!(sender.try_send(&[1, 2, 3, 4, 5]), Ok(5));
            assert_eq!(sender.try_send(&[6, 7, 8, 9]), Ok(4));
        });

        sleep(Duration::from_secs(1));

        let mut buffer = [0; 1024];
        let mut received = 0;
        while received < 9 {
            match receiver.try_recv(&mut buffer[received..]) {
                Ok(rec) => received += rec,
                Err(_) => panic!(),
            }
        }

        assert_eq!(buffer[0..7], [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_throughput() {
        let (mut sender, mut receiver) = super::shared_face::<1800>();

        let bytes_to_send = 1024 * 1024 * 10;

        std::thread::spawn(move || {
            let mut bytes_sent = 0;
            let buf = [12; 1024];
            while bytes_sent < bytes_to_send {
                let len = buf.len().min(bytes_to_send - bytes_sent);
                let sent = sender.try_send(&buf[..len]).unwrap();
                bytes_sent += sent;
            }
            drop(sender);
        });

        let mut buffer = [0; 1024 * 10];
        let mut received = 0;
        loop {
            match receiver.try_recv(&mut buffer[..]) {
                Ok(rec) => received += rec,
                Err(FaceError::Disconnected) => break,
            }
        }

        assert_eq!(received, bytes_to_send);
    }
}
