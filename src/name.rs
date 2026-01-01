use core::num::NonZeroU16;

use crate::{
    io::{Decode, Encode, Write},
    tlv::{TlvDecode, TlvEncode, TLV},
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameComponent<'a> {
    pub typ: NonZeroU16,
    pub bytes: &'a [u8],
}

impl<'a> NameComponent<'a> {
    pub const TYPE_GENERIC: u16 = 8;
    pub const TYPE_IMPLICIT_SHA256: u16 = 1;
    pub const TYPE_PARAMETER_SHA256: u16 = 2;
    pub const TYPE_KEYWORD: u16 = 32;
    pub const TYPE_SEGMENT: u16 = 50;
    pub const TYPE_BYTE_OFFSET: u16 = 52;
    pub const TYPE_VERSION_NAME: u16 = 54;
    pub const TYPE_TIMESTAMP: u16 = 56;
    pub const TYPE_SEQUENCE_NUM: u16 = 58;

    pub fn new(typ: u16, bytes: &'a [u8]) -> Option<Self> {
        Some(Self {
            typ: NonZeroU16::new(typ)?,
            bytes,
        })
    }

    pub fn generic(bytes: &'a [u8]) -> Self {
        Self {
            typ: NonZeroU16::new(Self::TYPE_GENERIC).unwrap(),
            bytes,
        }
    }

    pub fn implicit_sha256(bytes: &'a [u8]) -> Self {
        Self {
            typ: NonZeroU16::new(Self::TYPE_IMPLICIT_SHA256).unwrap(),
            bytes,
        }
    }

    pub fn parameter_sha256(bytes: &'a [u8]) -> Self {
        Self {
            typ: NonZeroU16::new(Self::TYPE_PARAMETER_SHA256).unwrap(),
            bytes,
        }
    }
}

impl<'a> Encode for NameComponent<'a> {
    fn encoded_length(&self) -> usize {
        TLV {
            typ: self.typ.into(),
            val: self.bytes,
        }
        .encoded_length()
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        TLV {
            typ: self.typ.into(),
            val: self.bytes,
        }
        .encode(writer)
    }
}

#[derive(Copy, Clone)]
pub struct Name<'a> {
    inner: NameInner<'a>,
}

impl<'a> Name<'a> {
    pub fn new() -> Self {
        Self {
            inner: NameInner::Empty,
        }
    }

    pub fn with_components(components: &'a [NameComponent<'a>]) -> Self {
        Name {
            inner: NameInner::Components {
                original: &Name {
                    inner: NameInner::Empty,
                },
                components,
                remaining_count: components.len(),
            },
        }
    }

    pub fn component_count(&self) -> usize {
        match self.inner {
            NameInner::Empty => 0,
            NameInner::Buffer {
                component_count, ..
            } => component_count,
            NameInner::Components {
                original,
                remaining_count,
                ..
            } => original.component_count() + remaining_count,
        }
    }

    pub fn dropping_last_component(&self) -> Option<Self> {
        match self.inner {
            NameInner::Empty => None,
            NameInner::Buffer {
                component_bytes,
                component_count,
                original_count,
            } => {
                if component_count == 1 {
                    return Some(Name {
                        inner: NameInner::Empty,
                    });
                }
                Some(Name {
                    inner: NameInner::Buffer {
                        component_bytes,
                        component_count: component_count - 1,
                        original_count,
                    },
                })
            }
            NameInner::Components {
                original,
                components,
                remaining_count,
            } => Some(if remaining_count == 1 {
                *original
            } else {
                Name {
                    inner: NameInner::Components {
                        original,
                        components,
                        remaining_count: remaining_count - 1,
                    },
                }
            }),
        }
    }

    pub fn adding_components(&'a self, components: &'a [NameComponent<'a>]) -> Self {
        Name {
            inner: NameInner::Components {
                original: self,
                components,
                remaining_count: components.len(),
            },
        }
    }

    pub fn components(&self) -> impl Iterator<Item = NameComponent<'a>> {
        let mut innermost_bytes = None;
        let mut innermost_count = 0;
        let mut free_components = 0;

        self.compute_iter(
            &mut innermost_bytes,
            &mut innermost_count,
            &mut free_components,
        );

        NameComponentIterator {
            innermost_bytes: innermost_bytes.map(|b| (b, 0)),
            innermost_remaining: innermost_count,
            free_components,
            name: *self,
        }
    }

    fn compute_iter(
        &self,
        innermost_bytes: &mut Option<&'a [u8]>,
        innermost_count: &mut usize,
        free_components: &mut usize,
    ) {
        match self.inner {
            NameInner::Empty => {}
            NameInner::Buffer {
                component_bytes,
                component_count,
                ..
            } => {
                *innermost_count = component_count;
                *innermost_bytes = Some(&component_bytes);
            }
            NameInner::Components {
                original,
                remaining_count,
                ..
            } => {
                *free_components += remaining_count;
                original.compute_iter(innermost_bytes, innermost_count, free_components)
            }
        }
    }
}

impl<'a> TlvEncode for Name<'a> {
    const TLV_TYPE: u32 = 7;

    fn inner_length(&self) -> usize {
        match self.inner {
            NameInner::Empty => 0,
            NameInner::Buffer {
                component_bytes,
                component_count,
                original_count,
            } => {
                if component_count == original_count {
                    component_bytes.len()
                } else {
                    // Must only take component_count components
                    let mut offset = 0;
                    let mut cc = 0;
                    while cc < component_count {
                        let nc_len = match TLV::try_decode(&component_bytes[offset..]) {
                            Ok((_, nc_len)) => nc_len,
                            Err(_) => unreachable!(), // otherwise would not have been created
                        };
                        cc += 1;
                        offset += nc_len;
                    }
                    offset
                }
            }
            NameInner::Components {
                original,
                components,
                remaining_count,
            } => {
                let mut len = original.inner_length();
                for i in 0..remaining_count {
                    let tlv = TLV {
                        typ: components[i].typ.into(),
                        val: &components[i].bytes,
                    };
                    len += tlv.encoded_length()
                }
                len
            }
        }
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        match self.inner {
            NameInner::Empty => Ok(()),
            NameInner::Buffer {
                component_bytes,
                component_count,
                original_count,
            } => {
                if component_count == original_count {
                    // Can copy unmodified buffer
                    writer.write(component_bytes)
                } else {
                    let mut offset = 0;
                    let mut cc = 0;
                    while cc < component_count {
                        let nc_len = match TLV::try_decode(&component_bytes[offset..]) {
                            Ok((_, nc_len)) => nc_len,
                            Err(_) => unreachable!(), // otherwise would not have been created
                        };
                        cc += 1;
                        offset += nc_len;
                    }
                    writer.write(&component_bytes[0..offset])
                }
            }
            NameInner::Components {
                original,
                components,
                remaining_count,
            } => {
                original.encode_inner(writer)?;
                for i in 0..remaining_count {
                    let tlv = TLV {
                        typ: components[i].typ.into(),
                        val: &components[i].bytes,
                    };
                    tlv.encode(writer)?;
                }
                Ok(())
            }
        }
    }
}

impl<'a> TlvDecode<'a> for Name<'a> {
    fn try_decode_from_inner(inner_bytes: &'a [u8]) -> Option<Name<'a>> {
        let mut component_count = 0;
        let mut offset = 0;
        while offset < inner_bytes.len() {
            let (nc_tlv, nc_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            let _: NonZeroU16 = nc_tlv.typ.try_into().ok()?;
            component_count += 1;
            offset += nc_len;
        }

        if offset != inner_bytes.len() {
            return None;
        }

        let inner = if component_count == 0 {
            NameInner::Empty
        } else {
            NameInner::Buffer {
                component_bytes: inner_bytes,
                component_count,
                original_count: component_count,
            }
        };

        Some(Name { inner })
    }
}

#[derive(Copy, Clone)]
enum NameInner<'a> {
    Empty,
    Buffer {
        component_bytes: &'a [u8],
        component_count: usize,
        original_count: usize,
    },
    Components {
        original: &'a Name<'a>,
        components: &'a [NameComponent<'a>],
        remaining_count: usize,
    },
}

struct NameComponentIterator<'a> {
    innermost_bytes: Option<(&'a [u8], usize)>,
    innermost_remaining: usize,
    free_components: usize,
    name: Name<'a>,
}

impl<'a> Iterator for NameComponentIterator<'a> {
    type Item = NameComponent<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // We first go to the original inner name which we know is
        //  at the core (if present at all), and then pick off added
        //  components one by one.
        if self.innermost_remaining == 0 {
            if self.free_components == 0 {
                return None;
            }
            self.innermost_bytes = None;
        }

        match self.innermost_bytes.as_mut() {
            Some((bytes, offset)) => {
                match TLV::try_decode(&bytes[*offset..]) {
                    Ok((nc_tlv, nc_len)) => {
                        *offset += nc_len;
                        self.innermost_remaining -= 1;
                        Some(NameComponent {
                            // Would not have been created
                            typ: nc_tlv.typ.try_into().unwrap(),
                            bytes: nc_tlv.val,
                        })
                    }
                    Err(_) => unreachable!(), // otherwise would not have been created
                }
            }
            None => {
                let mut nn = &self.name;
                let mut remaining_free_components = self.free_components;
                loop {
                    match nn.inner {
                        NameInner::Components {
                            original,
                            components,
                            remaining_count,
                        } => {
                            if remaining_free_components > remaining_count {
                                // The sought component is in a deeper chunk
                                nn = original;
                                remaining_free_components -= remaining_count;
                            } else {
                                self.free_components -= 1;
                                return Some(
                                    components[remaining_count - remaining_free_components],
                                );
                            }
                        }
                        _ => unreachable!(), // Because upon iterator creation we ensured the correct depth
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        io::{Decode, Encode},
        name::{Name, NameComponent},
        tlv::{TlvDecode, TlvEncode, TLV},
    };

    #[test]
    fn test_component() {
        let comp = NameComponent::generic(b"Hello");
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"Hello");

        let comp = NameComponent::implicit_sha256(b"");
        assert!(comp.typ.get() == NameComponent::TYPE_IMPLICIT_SHA256);
        assert!(comp.bytes == b"");

        let comp = NameComponent::parameter_sha256(b"parpar");
        assert!(comp.typ.get() == NameComponent::TYPE_PARAMETER_SHA256);
        assert!(comp.bytes == b"parpar");

        let comp = NameComponent::new(28, b"test");
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == 28);
        assert!(comp.bytes == b"test");

        let comp = NameComponent::new(0, b"none");
        assert!(comp.is_none());
    }

    #[test]
    fn test_basics() {
        let name = Name::new();
        assert_eq!(name.component_count(), 0);
        assert!(name.components().next().is_none());

        let comp = &[NameComponent::generic(b"Hello")];
        let name = name.adding_components(comp);
        assert_eq!(name.component_count(), 1);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"Hello");
        assert!(nc.next().is_none());

        let comp = &[NameComponent::implicit_sha256(b"CAFECAFE")];
        let name = name.adding_components(comp);
        assert_eq!(name.component_count(), 2);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"Hello");
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_IMPLICIT_SHA256);
        assert!(comp.bytes == b"CAFECAFE");
        assert!(nc.next().is_none());

        let name = name.dropping_last_component();
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(name.component_count(), 1);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"Hello");
        assert!(nc.next().is_none());

        let name = name.dropping_last_component();
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(name.component_count(), 0);

        let name = name.dropping_last_component();
        assert!(name.is_none());
    }

    #[test]
    fn test_decoding() {
        let inner_bytes = &[];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_some());
        let name = name.unwrap();
        assert!(name.component_count() == 0);
        assert!(name.components().next().is_none());

        let inner_bytes = &[8, 0];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_some());
        let name = name.unwrap();
        assert!(name.component_count() == 1);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == &[]);
        assert!(nc.next().is_none());

        let inner_bytes = &[8, 5, b'h', b'e', b'l', b'l', b'o'];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_some());
        let name = name.unwrap();
        assert!(name.component_count() == 1);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"hello");
        assert!(nc.next().is_none());

        let name = name.dropping_last_component();
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(name.component_count(), 0);

        let name = name.dropping_last_component();
        assert!(name.is_none());

        let inner_bytes = &[
            8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd',
        ];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_some());
        let name = name.unwrap();
        assert!(name.component_count() == 2);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"hello");
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_IMPLICIT_SHA256);
        assert!(comp.bytes == b"world");
        assert!(nc.next().is_none());

        let comp = &[NameComponent::parameter_sha256(b"CAFECAFE")];
        let name = name.adding_components(comp);
        assert_eq!(name.component_count(), 3);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"hello");
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_IMPLICIT_SHA256);
        assert!(comp.bytes == b"world");
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_PARAMETER_SHA256);
        assert!(comp.bytes == b"CAFECAFE");
        assert!(nc.next().is_none());

        let name = name.dropping_last_component();
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(name.component_count(), 2);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"hello");
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_IMPLICIT_SHA256);
        assert!(comp.bytes == b"world");
        assert!(nc.next().is_none());

        let name = name.dropping_last_component();
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(name.component_count(), 1);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"hello");
        assert!(nc.next().is_none());

        let comp = &[NameComponent::parameter_sha256(b"CAFECAFE")];
        let name = name.adding_components(comp);
        assert_eq!(name.component_count(), 2);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"hello");
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_PARAMETER_SHA256);
        assert!(comp.bytes == b"CAFECAFE");
        assert!(nc.next().is_none());

        let name = name.dropping_last_component();
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(name.component_count(), 1);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == NameComponent::TYPE_GENERIC);
        assert!(comp.bytes == b"hello");
        assert!(nc.next().is_none());

        let name = name.dropping_last_component();
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(name.component_count(), 0);

        let name = name.dropping_last_component();
        assert!(name.is_none());

        let inner_bytes = &[
            8, 5, b'h', b'e', b'l', b'l', b'o', 0, 5, b'w', b'o', b'r', b'l', b'd',
        ];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_none());

        let inner_bytes = &[
            8, 5, b'h', b'e', b'l', b'l', b'o', 1, 6, b'w', b'o', b'r', b'l', b'd',
        ];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_none());

        let inner_bytes = &[
            8, 5, b'h', b'e', b'l', b'l', b'o', 0, 5, b'w', b'o', b'r', b'l', b'd', 1,
        ];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_none());

        let inner_bytes = &[253, 251, 252, 0];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_some());
        let name = name.unwrap();
        assert!(name.component_count() == 1);
        let mut nc = name.components();
        let comp = nc.next();
        assert!(comp.is_some());
        let comp = comp.unwrap();
        assert!(comp.typ.get() == u16::from_be_bytes([251, 252]));
        assert!(comp.bytes == &[]);
        assert!(nc.next().is_none());

        let inner_bytes = &[254, 251, 252, 253, 254, 0];
        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_none());
    }

    #[test]
    fn test_iteration() {
        let inner_bytes = &[
            8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd',
        ];

        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_some());
        let name = name.unwrap();
        assert!(name.component_count() == 2);

        let comp = &[NameComponent::generic(b"a1")];
        let name = name.adding_components(comp);
        assert_eq!(name.component_count(), 3);

        for (ii, cc) in name.components().enumerate() {
            match ii {
                0 => assert!(cc.bytes == b"hello"),
                1 => assert!(cc.bytes == b"world"),
                2 => assert!(cc.bytes == b"a1"),
                _ => panic!(),
            }
        }

        let comp = &[
            NameComponent::generic(b"b1"),
            NameComponent::generic(b"b2"),
            NameComponent::generic(b"b3"),
        ];
        let name = name.adding_components(comp);
        assert_eq!(name.component_count(), 6);

        for (ii, cc) in name.components().enumerate() {
            match ii {
                0 => assert!(cc.bytes == b"hello"),
                1 => assert!(cc.bytes == b"world"),
                2 => assert!(cc.bytes == b"a1"),

                3 => assert!(cc.bytes == b"b1"),
                4 => assert!(cc.bytes == b"b2"),
                5 => assert!(cc.bytes == b"b3"),
                _ => panic!(),
            }
        }

        let name = name.dropping_last_component();
        assert!(name.is_some());
        let name = name.unwrap();
        assert_eq!(name.component_count(), 5);

        for (ii, cc) in name.components().enumerate() {
            match ii {
                0 => assert!(cc.bytes == b"hello"),
                1 => assert!(cc.bytes == b"world"),
                2 => assert!(cc.bytes == b"a1"),

                3 => assert!(cc.bytes == b"b1"),
                4 => assert!(cc.bytes == b"b2"),
                _ => panic!(),
            }
        }

        let comp = &[NameComponent::generic(b"c1"), NameComponent::generic(b"c2")];
        let name = name.adding_components(comp);
        assert_eq!(name.component_count(), 7);

        for (ii, cc) in name.components().enumerate() {
            match ii {
                0 => assert!(cc.bytes == b"hello"),
                1 => assert!(cc.bytes == b"world"),
                2 => assert!(cc.bytes == b"a1"),

                3 => assert!(cc.bytes == b"b1"),
                4 => assert!(cc.bytes == b"b2"),

                5 => assert!(cc.bytes == b"c1"),
                6 => assert!(cc.bytes == b"c2"),
                _ => panic!(),
            }
        }
    }

    use alloc::vec::Vec;

    #[test]
    fn test_encoding() {
        let inner_bytes = &[
            8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd',
        ];
        let outer_bytes = &[
            7, 14, 8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd',
        ];

        let name = Name::try_decode_from_inner(inner_bytes);
        assert!(name.is_some());
        let name = name.unwrap();
        assert!(name.component_count() == 2);

        let mut buf = Vec::new();
        assert!(name.encoded_length() == outer_bytes.len());
        let _ = name.encode(&mut buf);
        assert!(buf.as_slice() == outer_bytes);

        let tlv = TLV::try_decode(&buf);
        assert!(tlv.is_ok());
        let (tlv, tlv_len) = tlv.unwrap();
        assert!(tlv_len == outer_bytes.len());
        assert!(tlv.typ.get() == Name::TLV_TYPE);
        assert!(tlv.val == inner_bytes);

        let inner_bytes = &[
            8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd', 2, 8, b'C',
            b'A', b'F', b'E', b'C', b'A', b'F', b'E',
        ];
        let outer_bytes = &[
            7, 24, 8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd', 2, 8,
            b'C', b'A', b'F', b'E', b'C', b'A', b'F', b'E',
        ];
        let comp = &[NameComponent::parameter_sha256(b"CAFECAFE")];
        let name = name.adding_components(comp);

        let mut buf = Vec::new();
        assert!(name.encoded_length() == outer_bytes.len());
        let _ = name.encode(&mut buf);
        assert!(buf.as_slice() == outer_bytes);

        let tlv = TLV::try_decode(&buf);
        assert!(tlv.is_ok());
        let (tlv, tlv_len) = tlv.unwrap();
        assert!(tlv_len == outer_bytes.len());
        assert!(tlv.typ.get() == Name::TLV_TYPE);
        assert!(tlv.val == inner_bytes);

        let inner_bytes = &[8, 5, b'h', b'e', b'l', b'l', b'o'];
        let outer_bytes = &[7, 7, 8, 5, b'h', b'e', b'l', b'l', b'o'];
        let name = name
            .dropping_last_component()
            .unwrap()
            .dropping_last_component()
            .unwrap();

        let mut buf = Vec::new();
        assert!(name.encoded_length() == outer_bytes.len());
        let _ = name.encode(&mut buf);
        assert!(buf.as_slice() == outer_bytes);

        let tlv = TLV::try_decode(&buf);
        assert!(tlv.is_ok());
        let (tlv, tlv_len) = tlv.unwrap();
        assert!(tlv_len == outer_bytes.len());
        assert!(tlv.typ.get() == Name::TLV_TYPE);
        assert!(tlv.val == inner_bytes);
    }
}
