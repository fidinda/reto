
pub(crate) enum EncodingError {
    //BufferTooShort,
}


pub(crate) trait Buffer {
    fn push(&mut self, bytes: &[u8]) -> Result<(), EncodingError>;
}


pub(crate) trait Encodable {
    fn encoded_length(&self) -> usize;
    fn encode<B : Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError>;
}


use alloc::vec::Vec;

impl Buffer for Vec<u8> {
    fn push(&mut self, bytes: &[u8]) -> Result<(), EncodingError> {
        Ok(self.extend_from_slice(bytes))
    }
}
