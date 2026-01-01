pub trait Write {
    type Error;
    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub trait Encode {
    fn encoded_length(&self) -> usize;
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error>;
}

pub trait Decode<'a> {
    type Error;

    fn try_decode(bytes: &'a [u8]) -> Result<(Self, usize), Self::Error>
    where
        Self: Sized;
}

impl Write for Vec<u8> {
    type Error = ();

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}
