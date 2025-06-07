use core::num::NonZeroU16;

use crate::tlv::{Encode, EncodingError, Write, TLV};

#[derive(Copy, Clone)]
pub enum NameComponentType {
    Generic,
    ImplicitSha256Digest,
    ParameterSha256Digest,
    Other(NonZeroU16),
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameComponent<'a> {
    pub typ: NonZeroU16,
    pub bytes: &'a [u8],
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

    pub(crate) fn from_bytes(component_bytes: &'a [u8]) -> Option<Self> {
        let mut component_count = 0;
        let mut offset = 0;
        while offset < component_bytes.len() {
            let (nc_tlv, nc_len) = TLV::try_decode(&component_bytes[offset..]).ok()?;
            let _: NonZeroU16 = nc_tlv.typ.try_into().ok()?;
            component_count += 1;
            offset += nc_len;
        }

        let inner = if component_count == 0 {
            NameInner::Empty
        } else {
            NameInner::Buffer {
                component_bytes,
                component_count,
                original_count: component_count,
            }
        };

        Some(Name { inner })
    }

    pub fn component_count(&self) -> usize {
        match self.inner {
            NameInner::Empty => 0,
            NameInner::Buffer {
                component_count, ..
            } => component_count,
            NameInner::Component { original, .. } => original.component_count() + 1,
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
            NameInner::Component { original, .. } => Some(*original),
        }
    }

    pub fn adding_component(&'a self, component: NameComponent<'a>) -> Self {
        Name {
            inner: NameInner::Component {
                original: self,
                component,
            },
        }
    }

    // TODO: make double-ended, maybe?
    // Check https://doc.rust-lang.org/src/std/path.rs.html#1088-1090
    // Maybe we can do the same for iteration?
    // Could also pre-store the offsets of components, e.g. up to 4
    // So you keep track of the path and when iterating you actually modify
    // the path itself somehow (recreating the chain from scratch every time?)

    // Or we could just always parse the path into a equivalent repr
    // where the origin is always empty?
    // Could we do that without allocations?
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
            NameInner::Component { .. } => {
                *free_components += 1;
                self.compute_iter(innermost_bytes, innermost_count, free_components)
            }
        }
    }

    fn component_len(&self) -> usize {
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
            NameInner::Component {
                original,
                component,
            } => {
                let tlv = TLV {
                    typ: component.typ.into(),
                    val: &component.bytes,
                };
                original.component_len() + tlv.encoded_length()
            }
        }
    }

    fn component_encode<W: Write>(&self, writer: &mut W) -> Result<(), EncodingError> {
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
            NameInner::Component {
                original,
                component,
            } => {
                original.component_encode(writer)?;
                let tlv = TLV {
                    typ: component.typ.into(),
                    val: &component.bytes,
                };
                tlv.encode(writer)
            }
        }
    }
}

const TLV_TYPE_NAME: u32 = 7;

impl<'a> Encode for Name<'a> {
    fn encoded_length(&self) -> usize {
        let component_len = self.component_len();
        (TLV_TYPE_NAME as u64).encoded_length()
            + (component_len as u64).encoded_length()
            + component_len
    }

    fn encode<W: Write>(&self, writer: &mut W) -> Result<(), EncodingError> {
        let component_len = self.component_len();
        (TLV_TYPE_NAME as u64).encode(writer)?;
        (component_len as u64).encode(writer)?;
        self.component_encode(writer)
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
    Component {
        original: &'a Name<'a>,
        component: NameComponent<'a>,
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
        if self.innermost_remaining == 0 {
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
                //TODO: this is very much untested, probable off-by one errors
                let mut depth = 0;
                let mut nn = self.name;
                let mut cc = None;
                while depth < self.free_components {
                    depth += 1;
                    (nn, cc) = match nn.inner {
                        NameInner::Component {
                            original,
                            component,
                        } => (*original, Some(component)),
                        _ => unreachable!(), // Because upon iterator creation we ensured the correct depth
                    };
                }
                self.free_components -= 1;
                cc
            }
        }
    }
}

impl From<NonZeroU16> for NameComponentType {
    fn from(value: NonZeroU16) -> Self {
        match value.get() {
            NAME_COMPONENT_TYPE_GENERIC => NameComponentType::Generic,
            NAME_COMPONENT_TYPE_IMPLICIT_SHA256 => NameComponentType::ImplicitSha256Digest,
            NAME_COMPONENT_TYPE_PARAMETER_SHA256 => NameComponentType::ParameterSha256Digest,
            v => NameComponentType::Other(v.try_into().unwrap()),
        }
    }
}

impl From<NameComponentType> for NonZeroU16 {
    fn from(value: NameComponentType) -> Self {
        match value {
            NameComponentType::Generic => NAME_COMPONENT_TYPE_GENERIC.try_into().unwrap(),
            NameComponentType::ImplicitSha256Digest => {
                NAME_COMPONENT_TYPE_IMPLICIT_SHA256.try_into().unwrap()
            }
            NameComponentType::ParameterSha256Digest => {
                NAME_COMPONENT_TYPE_PARAMETER_SHA256.try_into().unwrap()
            }
            NameComponentType::Other(v) => v,
        }
    }
}

const NAME_COMPONENT_TYPE_GENERIC: u16 = 8;
const NAME_COMPONENT_TYPE_IMPLICIT_SHA256: u16 = 1;
const NAME_COMPONENT_TYPE_PARAMETER_SHA256: u16 = 2;

impl<'a> NameComponent<'a> {
    pub fn new(typ: NameComponentType, bytes: &'a [u8]) -> Self {
        Self {
            typ: typ.into(),
            bytes,
        }
    }

    pub fn component_type(&self) -> NameComponentType {
        self.typ.into()
    }
}
