use core::num::NonZeroU32;

use crate::io::{Decode, Encode, Write};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VarintDecodingError {
    BufferTooShort,
    NonMinimalIntegerEncoding,
    InvalidValue,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlvDecodingError {
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodingError {
    TlvDecodingError(TlvDecodingError),
    WrongTlvType,
    InnerDecodingError,
}

pub trait TlvEncode {
    const TLV_TYPE: u32;

    fn inner_length(&self) -> usize;
    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error>;
}

pub trait TlvDecode<'a>: TlvEncode {
    fn try_decode_from_inner(inner_bytes: &'a [u8]) -> Option<Self>
    where
        Self: Sized;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TLV<'a> {
    pub typ: NonZeroU32,
    pub val: &'a [u8],
}

impl<'a> TLV<'a> {
    // This matters when the evolution of the protocol requires adding new types.
    // When an unknown type is critical we must signal error, otherwise we can ignore it.
    pub fn type_is_critical(&self) -> bool {
        let typ = self.typ.get();
        typ < 32 || typ & 1 == 1
    }
}

impl<'a> Decode<'a> for TLV<'a> {
    type Error = TlvDecodingError;

    fn try_decode(bytes: &'a [u8]) -> Result<(TLV<'a>, usize), Self::Error> {
        let mut cursor = 0;
        let (typ, typ_len) = Varint::try_decode(&bytes[cursor..])
            .map_err(|err| TlvDecodingError::CannotDecodeType { err })?;
        cursor += typ_len;

        let typ: u32 = typ
            .0
            .try_into()
            .map_err(|_| TlvDecodingError::CannotDecodeType {
                err: VarintDecodingError::InvalidValue,
            })?;
        let typ = NonZeroU32::new(typ).ok_or(TlvDecodingError::CannotDecodeType {
            err: VarintDecodingError::InvalidValue,
        })?;

        let (len, len_len) = Varint::try_decode(&bytes[cursor..])
            .map_err(|err| TlvDecodingError::CannotDecodeLength { typ, err })?;
        cursor += len_len;

        let len: usize = len
            .0
            .try_into()
            .map_err(|_| TlvDecodingError::CannotDecodeLength {
                typ,
                err: VarintDecodingError::InvalidValue,
            })?;

        if cursor + len > bytes.len() {
            return Err(TlvDecodingError::CannotDecodeValue { typ, len });
        }

        let val = &bytes[cursor..(cursor + len)];
        Ok((TLV { typ, val }, cursor + len))
    }
}

impl<'a> Encode for TLV<'a> {
    fn encoded_length(&self) -> usize {
        let l = self.val.len();
        Varint(self.typ.get() as u64).encoded_length() + Varint(l as u64).encoded_length() + l
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        Varint(self.typ.get() as u64).encode(writer)?;
        Varint(self.val.len() as u64).encode(writer)?;
        writer.write(&self.val)
    }
}

impl<'a> Decode<'a> for u64 {
    type Error = ();

    fn try_decode(bytes: &[u8]) -> Result<(u64, usize), Self::Error> {
        match bytes.len() {
            1 => Ok((bytes[0] as u64, 1)),
            2 => Ok((u16::from_be_bytes([bytes[0], bytes[1]]) as u64, 2)),
            4 => Ok((
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                4,
            )),
            8 => Ok((
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                8,
            )),
            _ => Err(()),
        }
    }
}

impl Encode for u64 {
    fn encoded_length(&self) -> usize {
        if *self <= 252 {
            1
        } else if *self <= 65535 {
            2
        } else if *self <= 4294967295 {
            4
        } else {
            8
        }
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        if *self <= 252 {
            writer.write(&[*self as u8])
        } else if *self <= 65535 {
            writer.write(&(*self as u16).to_be_bytes())
        } else if *self <= 4294967295 {
            writer.write(&(*self as u32).to_be_bytes())
        } else {
            writer.write(&self.to_be_bytes())
        }
    }
}

impl<E: Encode> Encode for Option<E> {
    fn encoded_length(&self) -> usize {
        match self {
            Some(inner) => inner.encoded_length(),
            None => 0,
        }
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        match self {
            Some(inner) => inner.encode(writer),
            None => Ok(()),
        }
    }
}

impl<E1: Encode, E2: Encode> Encode for (E1, E2) {
    fn encoded_length(&self) -> usize {
        self.0.encoded_length() + self.1.encoded_length()
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.0.encode(writer)?;
        self.1.encode(writer)
    }
}

impl<E1: Encode, E2: Encode, E3: Encode> Encode for (E1, E2, E3) {
    fn encoded_length(&self) -> usize {
        self.0.encoded_length() + self.1.encoded_length() + self.2.encoded_length()
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.0.encode(writer)?;
        self.1.encode(writer)?;
        self.2.encode(writer)
    }
}

impl<E: TlvEncode> Encode for E {
    fn encoded_length(&self) -> usize {
        let len = self.inner_length();
        Varint(Self::TLV_TYPE as u64).encoded_length() + Varint(len as u64).encoded_length() + len
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        Varint(Self::TLV_TYPE as u64).encode(writer)?;
        Varint(self.inner_length() as u64).encode(writer)?;
        self.encode_inner(writer)
    }
}

impl<'a, D: TlvDecode<'a>> Decode<'a> for D {
    type Error = DecodingError;

    fn try_decode(bytes: &'a [u8]) -> Result<(Self, usize), Self::Error>
    where
        Self: Sized,
    {
        let (tlv, tlv_len) =
            TLV::<'a>::try_decode(bytes).map_err(|e| DecodingError::TlvDecodingError(e))?;

        if tlv.typ.get() != Self::TLV_TYPE {
            return Err(DecodingError::WrongTlvType);
        }

        match Self::try_decode_from_inner(tlv.val) {
            Some(v) => Ok((v, tlv_len)),
            None => Err(DecodingError::InnerDecodingError),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TypedEmpty<const TYPE: u32> {}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TypedInteger<const TYPE: u32, I: Into<u64> + TryFrom<u64> + Copy> {
    pub val: I,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TypedBytes<'a, const TYPE: u32> {
    pub bytes: &'a [u8],
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TypedArray<const TYPE: u32, const LEN: usize> {
    pub bytes: [u8; LEN],
}

impl<const TYPE: u32> TlvEncode for TypedEmpty<TYPE> {
    const TLV_TYPE: u32 = TYPE;

    fn inner_length(&self) -> usize {
        0
    }

    fn encode_inner<W: Write + ?Sized>(&self, _writer: &mut W) -> Result<(), W::Error> {
        Ok(())
    }
}

impl<const TYPE: u32, I: Into<u64> + TryFrom<u64> + Copy> TlvEncode for TypedInteger<TYPE, I> {
    const TLV_TYPE: u32 = TYPE;

    fn inner_length(&self) -> usize {
        self.val.into().encoded_length()
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.val.into().encode(writer)
    }
}

impl<'a, const TYPE: u32> TlvEncode for TypedBytes<'a, TYPE> {
    const TLV_TYPE: u32 = TYPE;

    fn inner_length(&self) -> usize {
        self.bytes.len()
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        writer.write(&self.bytes)
    }
}

impl<'a, const TYPE: u32, const LEN: usize> TlvEncode for TypedArray<TYPE, LEN> {
    const TLV_TYPE: u32 = TYPE;

    fn inner_length(&self) -> usize {
        LEN
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        writer.write(&self.bytes)
    }
}

// Varint is used to encode T and L of the TLV, i.e. when we don't ex-ante know the length
//  of the number we are reading from the stream. Hence, it takes 1,3,5, or 9 bytes.
// The u64 above is instead used as the _value_ in a TLV, and we already know the length
//  from the L field in TLV, so the u64 can be encoded as 1,2,4, or 8 bytes.
struct Varint(u64);

impl Varint {
    pub fn try_decode(bytes: &[u8]) -> Result<(Self, usize), VarintDecodingError> {
        let len = bytes.len();
        if len == 0 {
            return Err(VarintDecodingError::BufferTooShort);
        }

        match bytes[0] {
            0..=252 => Ok((Self(bytes[0] as u64), 1)),
            253 => {
                if len < 3 {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let val = u16::from_be_bytes([bytes[1], bytes[2]]);
                if val > 252 {
                    Ok((Self(val as u64), 3))
                } else {
                    Err(VarintDecodingError::NonMinimalIntegerEncoding)
                }
            }
            254 => {
                if len < 5 {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let val = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                if val > 65535 {
                    Ok((Self(val as u64), 5))
                } else {
                    Err(VarintDecodingError::NonMinimalIntegerEncoding)
                }
            }
            255 => {
                if len < 9 {
                    return Err(VarintDecodingError::BufferTooShort);
                }
                let val = u64::from_be_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                if val > 4294967295 {
                    Ok((Self(val), 9))
                } else {
                    Err(VarintDecodingError::NonMinimalIntegerEncoding)
                }
            }
        }
    }
}

impl Encode for Varint {
    fn encoded_length(&self) -> usize {
        if self.0 <= 252 {
            1
        } else if self.0 <= 65535 {
            3
        } else if self.0 <= 4294967295 {
            5
        } else {
            9
        }
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        if self.0 <= 252 {
            writer.write(&[self.0 as u8])
        } else if self.0 <= 65535 {
            writer.write(&[253])?;
            writer.write(&(self.0 as u16).to_be_bytes())
        } else if self.0 <= 4294967295 {
            writer.write(&[254])?;
            writer.write(&(self.0 as u32).to_be_bytes())
        } else {
            writer.write(&[255])?;
            writer.write(&self.0.to_be_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;

    use crate::tlv::{Decode, Encode, TlvDecodingError, VarintDecodingError, TLV};
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
        assert_eq!(253u64.encoded_length(), 2);
        assert_eq!(254u64.encoded_length(), 2);
        assert_eq!(255u64.encoded_length(), 2);
        assert_eq!(256u64.encoded_length(), 2);
        assert_eq!(65535u64.encoded_length(), 2);
        assert_eq!(65536u64.encoded_length(), 4);
        assert_eq!(4294967295u64.encoded_length(), 4);
        assert_eq!(4294967296u64.encoded_length(), 8);
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
        let mut s2: SliceBuffer<2> = SliceBuffer {
            bytes: [0; 2],
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
        let mut s7: SliceBuffer<7> = SliceBuffer {
            bytes: [0; 7],
            cursor: 0,
        };
        let mut s8: SliceBuffer<8> = SliceBuffer {
            bytes: [0; 8],
            cursor: 0,
        };

        for v in (0u64..2)
            .chain(252..256)
            .chain(65535..65537)
            .chain(4294967295..4294967297)
        {
            buf.clear();
            s0.cursor = 0;
            s1.cursor = 0;
            s2.cursor = 0;
            s3.cursor = 0;
            s4.cursor = 0;
            s7.cursor = 0;
            s8.cursor = 0;

            let ret = v.encode(&mut buf);
            assert_eq!(ret, Ok(()));
            assert_eq!(v.encoded_length(), buf.len());
            let dec = u64::try_decode(&buf);
            assert!(dec.is_ok());
            let (dec, dec_len) = dec.unwrap();
            assert_eq!(dec, v);
            assert_eq!(dec_len, v.encoded_length());

            match v.encoded_length() {
                1 => {
                    assert_eq!(v.encode(&mut s0), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s1), Ok(()));
                    assert_eq!(v.encode(&mut s2), Ok(()));
                    assert_eq!(v.encode(&mut s3), Ok(()));
                    assert_eq!(v.encode(&mut s4), Ok(()));
                    assert_eq!(v.encode(&mut s7), Ok(()));
                    assert_eq!(v.encode(&mut s8), Ok(()));
                }
                2 => {
                    assert_eq!(v.encode(&mut s0), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s1), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s2), Ok(()));
                    assert_eq!(v.encode(&mut s3), Ok(()));
                    assert_eq!(v.encode(&mut s4), Ok(()));
                    assert_eq!(v.encode(&mut s7), Ok(()));
                    assert_eq!(v.encode(&mut s8), Ok(()));
                }
                4 => {
                    assert_eq!(v.encode(&mut s0), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s1), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s2), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s3), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s4), Ok(()));
                    assert_eq!(v.encode(&mut s7), Ok(()));
                    assert_eq!(v.encode(&mut s8), Ok(()));
                }
                8 => {
                    assert_eq!(v.encode(&mut s0), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s1), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s2), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s3), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s4), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s7), Err(BufferTooShort {}));
                    assert_eq!(v.encode(&mut s8), Ok(()));
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
            NonZeroU32::new(65535).unwrap(),
            NonZeroU32::new(65536).unwrap(),
            NonZeroU32::new(4294967295).unwrap(),
        ];

        for v in (0u64..2)
            .chain(252..256)
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
            Err(TlvDecodingError::CannotDecodeType {
                err: VarintDecodingError::BufferTooShort
            })
        );
        assert_eq!(
            TLV::try_decode(&[0]),
            Err(TlvDecodingError::CannotDecodeType {
                err: VarintDecodingError::InvalidValue
            })
        );
        assert_eq!(
            TLV::try_decode(&[255, 255, 255, 255, 255, 255, 255, 255, 255]),
            Err(TlvDecodingError::CannotDecodeType {
                err: VarintDecodingError::InvalidValue
            })
        );
        assert_eq!(
            TLV::try_decode(&[253, 0, 0]),
            Err(TlvDecodingError::CannotDecodeType {
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
            Err(TlvDecodingError::CannotDecodeLength {
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
            Err(TlvDecodingError::CannotDecodeLength {
                typ: NonZeroU32::new(1).unwrap(),
                err: VarintDecodingError::NonMinimalIntegerEncoding
            })
        );

        assert_eq!(
            TLV::try_decode(&[1, 5, 0, 0]),
            Err(TlvDecodingError::CannotDecodeValue {
                typ: NonZeroU32::new(1).unwrap(),
                len: 5
            })
        );
    }
}
