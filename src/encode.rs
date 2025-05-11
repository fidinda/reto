pub(crate) enum EncodingError {
    BufferTooShort,
}

pub(crate) trait Buffer {
    fn push(&mut self, bytes: &[u8]) -> Result<(), EncodingError>;
}

pub(crate) trait Encodable {
    fn encoded_length(&self) -> usize;
    fn encode<B: Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError>;
}

pub(crate) struct SliceBuffer<'a> {
    pub slice: &'a mut [u8],
    pub cursor: usize,
}

impl<'a> Buffer for SliceBuffer<'a> {
    fn push(&mut self, bytes: &[u8]) -> Result<(), EncodingError> {
        if self.cursor + bytes.len() > self.slice.len() {
            return Err(EncodingError::BufferTooShort);
        }
        let start = self.cursor;
        self.cursor += bytes.len();
        self.slice[start..self.cursor].copy_from_slice(bytes);
        Ok(())
    }
}
