use core::num::NonZeroU16;

use crate::{
    encode::{Buffer, Encodable, EncodingError},
    parse_tlvs, TLV,
};

#[derive(Copy, Clone)]
pub struct Name<'a> {
    inner: NameInner<'a>,
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

impl<'a> Name<'a> {
    pub fn new() -> Self {
        Self {
            inner: NameInner::Empty,
        }
    }

    pub(crate) fn from_bytes(component_bytes: &'a [u8]) -> Option<Self> {
        let mut component_count = 0;
        for nc in parse_tlvs(&component_bytes) {
            match nc {
                Ok(nc_tlv) => {
                    let _: NonZeroU16 = nc_tlv.tlv.typ.try_into().ok()?;
                    component_count += 1
                }
                Err(_) => return None,
            }
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

        let innermost_iter = innermost_bytes.map(|bytes| {
            parse_tlvs(bytes)
                .map(|tlv| {
                    // It would not have been created if there was an error
                    let tlv = tlv.ok().unwrap().tlv;
                    let typ: NonZeroU16 = tlv.typ.try_into().unwrap();
                    NameComponent {
                        typ,
                        bytes: tlv.val,
                    }
                })
                .take(innermost_count)
        });

        NameComponentIterator {
            innermost_iter,
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
                    let mut component_len = 0;
                    let mut cc = 0;
                    let mut parsed = parse_tlvs(component_bytes);
                    while cc < component_count {
                        cc += 1;
                        let n = parsed.next();
                        if cc == component_count {
                            component_len = n.unwrap().ok().unwrap().byte_range.1
                        }
                    }
                    component_len
                }
            }
            NameInner::Component {
                original,
                component,
            } => {
                let tlv: TLV<'_> = component.into();
                original.component_len() + tlv.encoded_length()
            }
        }
    }

    fn component_encode<B: Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        match self.inner {
            NameInner::Empty => Ok(()),
            NameInner::Buffer {
                component_bytes,
                component_count,
                original_count,
            } => {
                if component_count == original_count {
                    // Can copy unmodified buffer
                    buffer.push(component_bytes)
                } else {
                    let mut cc = 0;
                    let mut parsed = parse_tlvs(component_bytes);
                    while cc < component_count {
                        cc += 1;
                        if let Some(Ok(e)) = parsed.next() {
                            let tlv = e.tlv;
                            tlv.encode(buffer)?
                        } else {
                            unreachable!()
                        }
                    }
                    Ok(())
                }
            }
            NameInner::Component {
                original,
                component,
            } => {
                original.component_encode(buffer)?;
                let tlv: TLV<'_> = component.into();
                tlv.encode(buffer)
            }
        }
    }
}

const TLV_TYPE_NAME: u32 = 7;

impl<'a> Encodable for Name<'a> {
    fn encoded_length(&self) -> usize {
        let component_len = self.component_len();
        (TLV_TYPE_NAME as u64).encoded_length()
            + (component_len as u64).encoded_length()
            + component_len
    }

    fn encode<B: crate::encode::Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        let component_len = self.component_len();
        (TLV_TYPE_NAME as u64).encode(buffer)?;
        (component_len as u64).encode(buffer)?;
        self.component_encode(buffer)
    }
}

struct NameComponentIterator<'a, I>
where
    I: Iterator<Item = NameComponent<'a>>,
{
    innermost_iter: Option<I>,
    free_components: usize,
    name: Name<'a>,
}

impl<'a, I> Iterator for NameComponentIterator<'a, I>
where
    I: Iterator<Item = NameComponent<'a>>,
{
    type Item = NameComponent<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.innermost_iter.as_mut() {
            Some(i) => match i.next() {
                Some(v) => Some(v),
                None => {
                    self.innermost_iter = None;
                    self.next()
                }
            },
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

impl<'a> From<NameComponent<'a>> for TLV<'a> {
    fn from(value: NameComponent<'a>) -> Self {
        TLV {
            typ: value.typ.into(),
            val: &value.bytes,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NameComponent<'a> {
    pub typ: NonZeroU16,
    pub bytes: &'a [u8],
}

#[derive(Copy, Clone)]
pub enum NameComponentType {
    Generic,
    ImplicitSha256Digest,
    ParameterSha256Digest,
    Other(NonZeroU16),
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
