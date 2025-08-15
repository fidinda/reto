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

pub(crate) struct EncodedHasher<'a, const N: usize, H: Hasher<N>> {
    pub(crate) hasher: &'a mut H,
}

impl<'a, const N: usize, H: Hasher<N>> crate::io::Write for EncodedHasher<'a, N, H> {
    type Error = ();

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        Ok(self.hasher.update(bytes))
    }
}
