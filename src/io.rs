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
