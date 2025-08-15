use core::num::NonZeroU32;

use crate::io::Write;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VarintDecodingError {
    BufferTooShort,
    NonMinimalIntegerEncoding,
    InvalidValue,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

pub trait Encode {
    fn encoded_length(&self) -> usize;
    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
        let (typ, typ_len) = Self::parse_varint(&bytes[cursor..])
            .map_err(|err| DecodingError::CannotDecodeType { err })?;
        cursor += typ_len;

        let typ: u32 = typ
            .try_into()
            .map_err(|_| DecodingError::CannotDecodeType {
                err: VarintDecodingError::InvalidValue,
            })?;
        let typ = NonZeroU32::new(typ).ok_or(DecodingError::CannotDecodeType {
            err: VarintDecodingError::InvalidValue,
        })?;

        let (len, len_len) = Self::parse_varint(&bytes[cursor..])
            .map_err(|err| DecodingError::CannotDecodeLength { typ, err })?;
        cursor += len_len;

        let len: usize = len
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

    pub fn parse_varint(bytes: &[u8]) -> Result<(u64, usize), VarintDecodingError> {
        let len = bytes.len();
        if len == 0 {
            return Err(VarintDecodingError::BufferTooShort);
        }

        match bytes[0] {
            0..=252 => Ok((bytes[0] as u64, 1)),
            253 => {
                if len < 3 {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let val = u16::from_be_bytes(bytes[1..3].try_into().unwrap());
                if val > 252 {
                    Ok((val as u64, 3))
                } else {
                    Err(VarintDecodingError::NonMinimalIntegerEncoding)
                }
            }
            254 => {
                if len < 5 {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let val = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
                if val > 65535 {
                    Ok((val as u64, 5))
                } else {
                    Err(VarintDecodingError::NonMinimalIntegerEncoding)
                }
            }
            255 => {
                if len < 9 {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let val = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
                if val > 4294967295 {
                    Ok((val, 9))
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

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
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

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        (self.typ.get() as u64).encode(writer)?;
        (self.val.len() as u64).encode(writer)?;
        writer.write(&self.val)
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;

    use crate::tlv::{DecodingError, Encode, VarintDecodingError, TLV};
    use alloc::vec::Vec;

    impl super::Write for Vec<u8> {
        type Error = ();
        fn write(&mut self, bytes: &[u8]) -> Result<(), ()> {
            self.extend_from_slice(bytes);
            Ok(())
        }
    }

    struct SliceBuffer<const N: usize> {
        bytes: [u8; N],
        cursor: usize,
    }

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    struct BufferTooShort {}

    impl<const N: usize> super::Write for SliceBuffer<N> {
        type Error = BufferTooShort;
        fn write(&mut self, bytes: &[u8]) -> Result<(), BufferTooShort> {
            if self.cursor + bytes.len() <= N {
                self.bytes[self.cursor..(self.cursor + bytes.len())].copy_from_slice(bytes);
                self.cursor += bytes.len();
                return Ok(());
            }
            Err(BufferTooShort {})
        }
    }

    #[test]
    fn test_unsigned_size() {
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

    #[test]
    fn test_unsigned_encode_decode() {
        let mut buf = Vec::new();

        let mut s0: SliceBuffer<0> = SliceBuffer {
            bytes: [],
            cursor: 0,
        };
        let mut s1: SliceBuffer<1> = SliceBuffer {
            bytes: [0; 1],
            cursor: 0,
        };
        let mut s3: SliceBuffer<3> = SliceBuffer {
            bytes: [0; 3],
            cursor: 0,
        };
        let mut s4: SliceBuffer<4> = SliceBuffer {
            bytes: [0; 4],
            cursor: 0,
        };
        let mut s5: SliceBuffer<5> = SliceBuffer {
            bytes: [0; 5],
            cursor: 0,
        };
        let mut s8: SliceBuffer<8> = SliceBuffer {
            bytes: [0; 8],
            cursor: 0,
        };
        let mut s9: SliceBuffer<9> = SliceBuffer {
            bytes: [0; 9],
            cursor: 0,
        };

        for v in (0u64..256)
            .chain(65535..65537)
            .chain(4294967295..4294967297)
        {
            buf.clear();
            s0.cursor = 0;
            s1.cursor = 0;
            s3.cursor = 0;
            s4.cursor = 0;
            s5.cursor = 0;
            s8.cursor = 0;
            s9.cursor = 0;

            let ret = v.encode(&mut buf);
            assert_eq!(ret, Ok(()));
            assert_eq!(v.encoded_length(), buf.len());
            let dec = TLV::parse_varint(&buf);
            assert_eq!(dec.is_ok(), true);
            let (dec, dec_len) = dec.unwrap();
            assert_eq!(dec_len, v.encoded_length());
            assert_eq!(dec, v);

            match v.encoded_length() {
                1 => {
                    assert_eq!(v.encode(&mut s0), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s1), Ok(()));
                    assert_eq!(v.encode(&mut s3), Ok(()));
                    assert_eq!(v.encode(&mut s4), Ok(()));
                    assert_eq!(v.encode(&mut s5), Ok(()));
                    assert_eq!(v.encode(&mut s8), Ok(()));
                    assert_eq!(v.encode(&mut s9), Ok(()));
                }
                3 => {
                    assert_eq!(v.encode(&mut s0), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s1), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s3), Ok(()));
                    assert_eq!(v.encode(&mut s4), Ok(()));
                    assert_eq!(v.encode(&mut s5), Ok(()));
                    assert_eq!(v.encode(&mut s8), Ok(()));
                    assert_eq!(v.encode(&mut s9), Ok(()));
                }
                5 => {
                    assert_eq!(v.encode(&mut s0), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s1), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s3), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s4), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s5), Ok(()));
                    assert_eq!(v.encode(&mut s8), Ok(()));
                    assert_eq!(v.encode(&mut s9), Ok(()));
                }
                9 => {
                    assert_eq!(v.encode(&mut s0), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s1), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s3), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s4), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s5), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s8), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s9), Ok(()));
                }
                _ => panic!(),
            }
        }
    }

    #[test]
    fn test_tlv_encode_decode() {
        use alloc::vec::Vec;
        let mut buf = Vec::new();

        let types = [
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(252).unwrap(),
            NonZeroU32::new(255).unwrap(),
            NonZeroU32::new(256).unwrap(),
            NonZeroU32::new(256).unwrap(),
            NonZeroU32::new(65535).unwrap(),
            NonZeroU32::new(65536).unwrap(),
            NonZeroU32::new(4294967295).unwrap(),
        ];

        for v in (0u64..256)
            .chain(65535..65537)
            .chain(4294967295..4294967297)
        {
            use alloc::vec;
            let payload = vec![(v % 256) as u8; v as usize];

            for typ in types {
                buf.clear();
                let tlv = TLV { typ, val: &payload };
                let ret = tlv.encode(&mut buf);
                assert_eq!(ret, Ok(()));
                assert_eq!(tlv.encoded_length(), buf.len());
                let dec = TLV::try_decode(&buf);
                assert_eq!(dec.is_ok(), true);
                let (dec, dec_len) = dec.unwrap();
                assert_eq!(dec_len, tlv.encoded_length());
                assert_eq!(dec.typ, typ);
                assert_eq!(dec.val, &payload);

                let mut s0: SliceBuffer<0> = SliceBuffer {
                    bytes: [],
                    cursor: 0,
                };
                assert_eq!(tlv.encode(&mut s0), Err(BufferTooShort {}));
            }
        }

        assert_eq!(
            TLV::try_decode(&[]),
            Err(DecodingError::CannotDecodeType {
                err: VarintDecodingError::BufferTooShort
            })
        );
        assert_eq!(
            TLV::try_decode(&[0]),
            Err(DecodingError::CannotDecodeType {
                err: VarintDecodingError::InvalidValue
            })
        );
        assert_eq!(
            TLV::try_decode(&[255, 255, 255, 255, 255, 255, 255, 255, 255]),
            Err(DecodingError::CannotDecodeType {
                err: VarintDecodingError::InvalidValue
            })
        );
        assert_eq!(
            TLV::try_decode(&[253, 0, 0]),
            Err(DecodingError::CannotDecodeType {
                err: VarintDecodingError::NonMinimalIntegerEncoding
            })
        );

        assert_eq!(
            TLV::try_decode(&[1, 0]),
            Ok((
                TLV {
                    typ: NonZeroU32::new(1).unwrap(),
                    val: &[]
                },
                2
            ))
        );

        assert_eq!(
            TLV::try_decode(&[1, 0, 0]),
            Ok((
                TLV {
                    typ: NonZeroU32::new(1).unwrap(),
                    val: &[]
                },
                2
            ))
        );

        assert_eq!(
            TLV::try_decode(&[1]),
            Err(DecodingError::CannotDecodeLength {
                typ: NonZeroU32::new(1).unwrap(),
                err: VarintDecodingError::BufferTooShort
            })
        );

        assert_eq!(
            TLV::try_decode(&[1, 1, 1]),
            Ok((
                TLV {
                    typ: NonZeroU32::new(1).unwrap(),
                    val: &[1]
                },
                3
            ))
        );

        assert_eq!(
            TLV::try_decode(&[1, 253, 0, 0]),
            Err(DecodingError::CannotDecodeLength {
                typ: NonZeroU32::new(1).unwrap(),
                err: VarintDecodingError::NonMinimalIntegerEncoding
            })
        );

        assert_eq!(
            TLV::try_decode(&[1, 5, 0, 0]),
            Err(DecodingError::CannotDecodeValue {
                typ: NonZeroU32::new(1).unwrap(),
                len: 5
            })
        );
    }
}
