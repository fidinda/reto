pub trait Hasher {
    type Digest;
    fn reset(&mut self);
    fn update(&mut self, input: &[u8]);
    fn finalize_reset(&mut self) -> Self::Digest;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Sha256Digest(pub [u8; 32]);
