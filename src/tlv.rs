use core::num::NonZeroU32;
use crate::encode::{Buffer, Encodable, EncodingError};


pub enum DecodingError {
    BufferTooShort,
    NonMinimalIntegerEncoding,
    TypeInvalid,
    LengthInvalid,
}


#[derive(Copy, Clone)]
pub struct TLV<'a> {
    pub typ: NonZeroU32,
    pub val: &'a [u8]
}

impl<'a> TLV<'a> {
    // This matters when the evolution of the protocol requires adding new types.
    // When an unknown type is critical we must signal error, otherwise we can ignore it.
    pub fn is_critical(&self) -> bool {
        let typ = self.typ.get();
        typ < 32 || typ & 1 == 1
    }

    pub fn value_as_unsigned(&self) -> Option<u64> {
        match self.val.len() {
            1 => {
                Some(self.val[0] as u64)
            },
            2 => {
                Some(u16::from_be_bytes(self.val.try_into().ok()?) as u64)
            },
            4 => {
                Some(u32::from_be_bytes(self.val.try_into().ok()?) as u64)
            },
            8 => {
                Some(u64::from_be_bytes(self.val.try_into().ok()?))
            },
            _ => None
        }
    }
}


impl Encodable for u64 {
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

    fn encode<B : Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        if *self <= 252 {
            buffer.push(&[*self as u8])
        } else if *self <= 65535 {
            buffer.push(&[253])?;
            buffer.push(&(*self as u16).to_be_bytes())
        } else if *self <= 4294967295 {
            buffer.push(&[254])?;
            buffer.push(&(*self as u32).to_be_bytes())
        } else {
            buffer.push(&[255])?;
            buffer.push(&self.to_be_bytes())
        }
    }
}



pub struct TLVEntry<'a> {
    pub tlv: TLV<'a>,
    pub byte_range: (usize, usize)
}


pub fn parse_tlvs<'a>(bytes: &'a [u8]) -> impl Iterator<Item = Result<TLVEntry<'a>, DecodingError>> {
    TLVParser { bytes, cursor: 0 }
}


struct TLVParser<'a> {
    bytes: &'a [u8],
    cursor: usize
}

impl<'a> Iterator for TLVParser<'a> {
    type Item = Result<TLVEntry<'a>, DecodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.bytes.len() - self.cursor {
            0 => None,
            _ => Some(self.parse_next())
        }
    }
}


impl<'a> TLVParser<'a> {
    fn parse_next(&mut self) -> Result<TLVEntry<'a>, DecodingError> {
        let offset = self.cursor;
        let typ : u32 = self.parse_varint()?.try_into().map_err(|_| DecodingError::TypeInvalid)?;
        let typ = NonZeroU32::new(typ).ok_or(DecodingError::TypeInvalid)?;
        let len : usize = self.parse_varint()?.try_into().map_err(|_| DecodingError::LengthInvalid)?;
        if self.cursor + len > self.bytes.len() {
            return Err(DecodingError::BufferTooShort);
        }
        let val = &self.bytes[self.cursor..(self.cursor+len)];
        self.cursor += len;
        Ok(TLVEntry { tlv: TLV { typ, val }, byte_range: (offset, self.cursor) })
    }

    fn parse_varint(&mut self) -> Result<u64, DecodingError> {
        let first = self.bytes[self.cursor];
        self.cursor += 1;
        match first {
            0..=252 => Ok(first as u64),
            253 => {
                if self.cursor + 2 >= self.bytes.len() {
                    return Err(DecodingError::BufferTooShort)
                }
                let next : [u8;2] = self.bytes[self.cursor..(self.cursor + 2)].try_into().unwrap();
                self.cursor += 2;
                let val = u16::from_be_bytes(next); 
                if val > 252 {
                    Ok(val as u64)
                } else {
                    Err(DecodingError::NonMinimalIntegerEncoding)
                }
            },
            254 => {
                if self.cursor + 4 >= self.bytes.len() {
                    return Err(DecodingError::BufferTooShort)
                }
                let next : [u8;4] = self.bytes[self.cursor..(self.cursor + 4)].try_into().unwrap();
                self.cursor += 4;
                let val = u32::from_be_bytes(next); 
                if val > 65535 {
                    Ok(val as u64)
                } else {
                    Err(DecodingError::NonMinimalIntegerEncoding)
                }
            },
            255 => {
                if self.cursor + 8 >= self.bytes.len() {
                    return Err(DecodingError::BufferTooShort)
                }
                let next : [u8;8] = self.bytes[self.cursor..(self.cursor + 8)].try_into().unwrap();
                self.cursor += 8;
                let val = u64::from_be_bytes(next); 
                if val > 4294967295 {
                    Ok(val)
                } else {
                    Err(DecodingError::NonMinimalIntegerEncoding)
                }
            },
        }
    }
}

impl<'a> Encodable for TLV<'a> {
    fn encoded_length(&self) -> usize {
        let l = self.val.len();
        (self.typ.get() as u64).encoded_length()
        + (l as u64).encoded_length()
        + l
    }

    fn encode<B : crate::encode::Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        (self.typ.get() as u64).encode(buffer)?;
        (self.val.len() as u64).encode(buffer)?;
        buffer.push(&self.val)
    }
}




/*impl<'a, 'b, T> Encodable for T where &'b T : Into<TLV<'a>>, T: 'b {
    fn encoded_length(&self) -> usize {
        let tlv : TLV<'_> = self.into();
        let l = tlv.val.len();
        (tlv.typ.get() as u64).encoded_length()
        + (l as u64).encoded_length()
        + l
    }

    fn encode<B : Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        let tlv : TLV<'_> = self.into();
        (tlv.typ.get() as u64).encode(buffer)?;
        (tlv.val.len() as u64).encode(buffer)?;
        buffer.push(&tlv.val)
    }
}*/


#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn test_unsigned() {
        /*for v in 0..252 {
            assert_eq!(TLV::unsigned_encoded_length(v), 1);
        }
        assert_eq!(TLV::unsigned_encoded_length(253), 3);
        assert_eq!(TLV::unsigned_encoded_length(254), 3);
        assert_eq!(TLV::unsigned_encoded_length(255), 3);
        assert_eq!(TLV::unsigned_encoded_length(256), 3);
        assert_eq!(TLV::unsigned_encoded_length(65535), 3);
        assert_eq!(TLV::unsigned_encoded_length(65536), 5);
        assert_eq!(TLV::unsigned_encoded_length(4294967295), 5);
        assert_eq!(TLV::unsigned_encoded_length(4294967296), 9);*/
    }
}
