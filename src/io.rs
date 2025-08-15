pub trait Write {
    type Error;
    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}
