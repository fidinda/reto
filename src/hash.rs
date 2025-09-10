pub trait Digest<const N: usize> {
    fn into_inner(self) -> [u8; N];
}

pub trait Hasher<const N: usize> {
    type Digest: Digest<N>;
    fn reset(&mut self);
    fn update(&mut self, input: &[u8]);
    fn finalize(&mut self) -> Self::Digest;
}

pub struct Sha256Digest {
    digest: [u8; 32],
}

impl Digest<32> for Sha256Digest {
    fn into_inner(self) -> [u8; 32] {
        self.digest
    }
}
