use core::future::Future;

use crate::Timestamp;

pub trait Hasher<const N: usize> {
    fn update(&mut self, input: &[u8]);
    fn finalize(self) -> [u8; N];
}

pub trait Platform {
    // Task spawning (which is currently needed for receiving from multiple faces asynchronously)
    type Task<T>; // Is assumed that the execution of the task is stopped when this is dropped
    fn spawn<T: 'static>(&self, future: impl Future<Output = T> + 'static) -> Self::Task<T>;

    // Time
    fn now() -> Timestamp;

    // Hashing
    fn sha256hasher() -> impl Hasher<32>;
}
