use core::num::NonZeroU32;

pub enum VarintDecodingError {
    BufferTooShort,
    NonMinimalIntegerEncoding,
    InvalidValue,
}

pub enum DecodingError {
    CannotDecodeType {
        err: VarintDecodingError,
    },
    CannotDecodeLength {
        typ: NonZeroU32,
        err: VarintDecodingError,
    },
    CannotDecodeValue {
        typ: NonZeroU32,
        len: usize,
    },
}

pub enum EncodingError {
    BufferTooShort,
}

pub trait Write {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodingError>;
}

pub trait Encode {
    fn encoded_length(&self) -> usize;
    fn encode<W: Write>(&self, writer: &mut W) -> Result<(), EncodingError>;
}

#[derive(Copy, Clone)]
pub struct TLV<'a> {
    pub typ: NonZeroU32,
    pub val: &'a [u8],
}

impl<'a> TLV<'a> {
    // This matters when the evolution of the protocol requires adding new types.
    // When an unknown type is critical we must signal error, otherwise we can ignore it.
    pub fn is_critical(&self) -> bool {
        let typ = self.typ.get();
        typ < 32 || typ & 1 == 1
    }

    pub fn val_as_u64(&self) -> Option<u64> {
        match self.val.len() {
            1 => Some(self.val[0] as u64),
            2 => Some(u16::from_be_bytes(self.val.try_into().ok()?) as u64),
            4 => Some(u32::from_be_bytes(self.val.try_into().ok()?) as u64),
            8 => Some(u64::from_be_bytes(self.val.try_into().ok()?)),
            _ => None,
        }
    }
}

impl<'a> TLV<'a> {
    pub fn try_decode(bytes: &'a [u8]) -> Result<(TLV<'a>, usize), DecodingError> {
        let mut cursor = 0;
        let typ: u32 = Self::parse_varint(bytes, &mut cursor)
            .map_err(|err| DecodingError::CannotDecodeType { err })?
            .try_into()
            .map_err(|_| DecodingError::CannotDecodeType {
                err: VarintDecodingError::InvalidValue,
            })?;
        let typ = NonZeroU32::new(typ).ok_or(DecodingError::CannotDecodeType {
            err: VarintDecodingError::InvalidValue,
        })?;

        let len: usize = Self::parse_varint(bytes, &mut cursor)
            .map_err(|err| DecodingError::CannotDecodeLength { typ, err })?
            .try_into()
            .map_err(|_| DecodingError::CannotDecodeLength {
                typ,
                err: VarintDecodingError::InvalidValue,
            })?;

        if cursor + len > bytes.len() {
            return Err(DecodingError::CannotDecodeValue { typ, len });
        }

        let val = &bytes[cursor..(cursor + len)];
        Ok((TLV { typ, val }, cursor + len))
    }

    fn parse_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, VarintDecodingError> {
        let first = bytes[*cursor];
        *cursor += 1;
        match first {
            0..=252 => Ok(first as u64),
            253 => {
                if *cursor + 2 >= bytes.len() {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let next: [u8; 2] = bytes[*cursor..(*cursor + 2)].try_into().unwrap();
                *cursor += 2;
                let val = u16::from_be_bytes(next);
                if val > 252 {
                    Ok(val as u64)
                } else {
                    Err(VarintDecodingError::NonMinimalIntegerEncoding)
                }
            }
            254 => {
                if *cursor + 4 >= bytes.len() {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let next: [u8; 4] = bytes[*cursor..(*cursor + 4)].try_into().unwrap();
                *cursor += 4;
                let val = u32::from_be_bytes(next);
                if val > 65535 {
                    Ok(val as u64)
                } else {
                    Err(VarintDecodingError::NonMinimalIntegerEncoding)
                }
            }
            255 => {
                if *cursor + 8 >= bytes.len() {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let next: [u8; 8] = bytes[*cursor..(*cursor + 8)].try_into().unwrap();
                *cursor += 8;
                let val = u64::from_be_bytes(next);
                if val > 4294967295 {
                    Ok(val)
                } else {
                    Err(VarintDecodingError::NonMinimalIntegerEncoding)
                }
            }
        }
    }
}

impl Encode for u64 {
    fn encoded_length(&self) -> usize {
        if *self <= 252 {
            1
        } else if *self <= 65535 {
            3
        } else if *self <= 4294967295 {
            5
        } else {
            9
        }
    }

    fn encode<W: Write>(&self, writer: &mut W) -> Result<(), EncodingError> {
        if *self <= 252 {
            writer.write(&[*self as u8])
        } else if *self <= 65535 {
            writer.write(&[253])?;
            writer.write(&(*self as u16).to_be_bytes())
        } else if *self <= 4294967295 {
            writer.write(&[254])?;
            writer.write(&(*self as u32).to_be_bytes())
        } else {
            writer.write(&[255])?;
            writer.write(&self.to_be_bytes())
        }
    }
}

impl<'a> Encode for TLV<'a> {
    fn encoded_length(&self) -> usize {
        let l = self.val.len();
        (self.typ.get() as u64).encoded_length() + (l as u64).encoded_length() + l
    }

    fn encode<W: Write>(&self, writer: &mut W) -> Result<(), EncodingError> {
        (self.typ.get() as u64).encode(writer)?;
        (self.val.len() as u64).encode(writer)?;
        writer.write(&self.val)
    }
}

#[cfg(test)]
mod tests {
    use crate::tlv::Encode;

    #[test]
    fn test_unsigned() {
        for v in 0u64..252 {
            assert_eq!(v.encoded_length(), 1);
        }
        assert_eq!(253u64.encoded_length(), 3);
        assert_eq!(254u64.encoded_length(), 3);
        assert_eq!(255u64.encoded_length(), 3);
        assert_eq!(256u64.encoded_length(), 3);
        assert_eq!(65535u64.encoded_length(), 3);
        assert_eq!(65536u64.encoded_length(), 5);
        assert_eq!(4294967295u64.encoded_length(), 5);
        assert_eq!(4294967296u64.encoded_length(), 9);
    }
}
