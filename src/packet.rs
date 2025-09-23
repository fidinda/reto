use crate::{
    hash::Hasher,
    io::Write,
    name::{Name, NameComponent},
    tlv::{Encode, TlvEncode, TypedArray, TypedBytes, TypedEmpty, TypedInteger, TLV},
};
use core::num::NonZeroU16;

pub struct Interest<'a> {
    pub name: Name<'a>,
    pub can_be_prefix: Option<CanBePrefix>,
    pub must_be_fresh: Option<MustBeFresh>,
    pub forwarding_hint: Option<ForwardingHint<'a>>,
    pub nonce: Option<InterestNonce>,
    pub interest_lifetime: Option<InterestLifetime>,
    pub hop_limit: Option<HopLimit>,
    pub application_parameters: Option<(
        ApplicationParameters<'a>,
        Option<(InterestSignatureInfo<'a>, InterestSignatureValue<'a>)>,
    )>,

    // The specification allows for any number of TLVs that are not currently known,
    //  but that should still be preserved.
    // If any unknown TLV has a critical type, we must stop procesing the packet.
    // To avoid allocations we keep an array of pointers to _possible_ places
    //  where zero or more unknown TLVs might happen. We store them as slices.
    // They cannot occur before name or after the signature.
    pub unknown_tlvs: [&'a [u8]; 7],
}

impl<'a> Interest<'a> {
    pub fn new(name: Name<'a>, can_be_prefix: bool, nonce: [u8; 4]) -> Self {
        let can_be_prefix = if can_be_prefix {
            Some(CanBePrefix {})
        } else {
            None
        };

        Self {
            name,
            can_be_prefix,
            must_be_fresh: None,
            forwarding_hint: None,
            nonce: Some(InterestNonce { bytes: nonce }),
            interest_lifetime: None,
            hop_limit: None,
            application_parameters: None,
            unknown_tlvs: Default::default(),
        }
    }

    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut offset = 0;

        let (name_tlv, name_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
        if name_tlv.typ.get() != Name::TLV_TYPE {
            return None; // Name must be the first TLV
        }
        offset += name_len;
        let name = Name::try_decode(name_tlv.val)?;

        // The rest should typically be a few known TLVs in order,
        //  but they may contain arbitrary non-critical TLVs too.
        // We store those as byte ranges each of which can contain zero or more TLVs.
        let mut can_be_prefix = None;
        let mut must_be_fresh = None;
        let mut forwarding_hint = None;
        let mut nonce = None;
        let mut interest_lifetime = None;
        let mut hop_limit = None;
        let mut application_parameters = None;
        let mut unknown_tlv_ranges = [(0usize, 0usize); 7];

        let known = [
            CanBePrefix::TLV_TYPE,
            MustBeFresh::TLV_TYPE,
            ForwardingHint::TLV_TYPE,
            InterestNonce::TLV_TYPE,
            InterestLifetime::TLV_TYPE,
            HopLimit::TLV_TYPE,
            ApplicationParameters::TLV_TYPE,
        ];
        let mut minimum_possible_known = 0;

        while offset < inner_bytes.len() {
            let (tlv, tlv_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            let typ = tlv.typ.get();
            if let Some(idx) = known.iter().position(|x| &typ == x) {
                // It is one of the known and expected TLVs
                if idx < minimum_possible_known {
                    return None; // ...but the order of known elements is incorrect
                }

                match idx {
                    0 => can_be_prefix = Some(CanBePrefix {}),
                    1 => must_be_fresh = Some(MustBeFresh {}),
                    2 => forwarding_hint = Some(ForwardingHint { bytes: tlv.val }),
                    3 => {
                        nonce = Some(InterestNonce {
                            bytes: tlv.val.try_into().ok()?,
                        })
                    }
                    4 => {
                        interest_lifetime = Some(InterestLifetime {
                            val: tlv.val_as_u64()?,
                        })
                    }
                    5 => {
                        hop_limit = Some(HopLimit {
                            val: tlv.val_as_u64()?.try_into().ok()?,
                        })
                    }
                    6 => application_parameters = Some(ApplicationParameters { bytes: tlv.val }),
                    _ => unreachable!(),
                }
                minimum_possible_known = idx;
            } else {
                // It is an unknown TLV
                if tlv.type_is_critical() {
                    return None; // There is a critical unknown type, so we must bail
                }

                // Check if we already have something in this range
                if unknown_tlv_ranges[minimum_possible_known] == (0, 0) {
                    unknown_tlv_ranges[minimum_possible_known] = (offset, offset + tlv_len)
                } else {
                    debug_assert!(unknown_tlv_ranges[minimum_possible_known].1 == offset);
                    unknown_tlv_ranges[minimum_possible_known].1 += tlv_len;
                }
            }

            offset += tlv_len;
        }

        let unknown_tlvs = unknown_tlv_ranges.map(|(b, e)| &inner_bytes[b..e]);

        let application_parameters = match application_parameters {
            Some(ap) => {
                // There can be an optional signature here
                let mut signature = None;
                if offset < inner_bytes.len() {
                    let (si_tlv, si_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
                    if si_tlv.typ.get() != InterestSignatureInfo::TLV_TYPE {
                        return None;
                    }
                    let si = InterestSignatureInfo::try_decode(si_tlv.val)?;
                    offset += si_len;
                    let (sv_tlv, sv_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
                    if sv_tlv.typ.get() != InterestSignatureValue::TLV_TYPE {
                        return None;
                    }
                    let sv = InterestSignatureValue { bytes: sv_tlv.val };
                    if offset + sv_len != inner_bytes.len() {
                        return None;
                    }
                    signature = Some((si, sv))
                }
                Some((ap, signature))
            }
            None => None,
        };

        Some(Interest {
            name,
            can_be_prefix,
            must_be_fresh,
            forwarding_hint,
            nonce,
            interest_lifetime,
            hop_limit,
            application_parameters,
            unknown_tlvs,
        })
    }

    pub fn hash_signed_portion<H: Hasher>(&self, hasher: &mut H) -> bool {
        let mut relevant_name = self.name;
        if let Some(last_component) = relevant_name.components().last() {
            if last_component.typ.get() == NameComponent::TYPE_PARAMETER_SHA256 {
                relevant_name = relevant_name.dropping_last_component().unwrap();
            }
        }

        let mut hh = EncodedHasher { hasher };
        let _ = relevant_name.encode(&mut hh);

        let (application_parameters, signature_info) = match self.application_parameters.as_ref() {
            Some((ap, signature)) => match signature {
                Some((signature_info, _)) => (ap, signature_info),
                None => return false,
            },
            None => return false,
        };

        let _ = application_parameters.encode(&mut hh);
        let _ = signature_info.encode(&mut hh);

        true
    }

    pub(crate) fn index_of_hop_byte_in_encoded_tlv(&self) -> Option<usize> {
        if self.hop_limit.is_none() {
            return None;
        }

        let mut len = (self.encoded_length() as u64).encoded_length()
            + (Self::TLV_TYPE as u64).encoded_length();
        len += self.unknown_tlvs[0].len();
        len += self.can_be_prefix.encoded_length();
        len += self.unknown_tlvs[1].len();
        len += self.must_be_fresh.encoded_length();
        len += self.unknown_tlvs[2].len();
        len += self.forwarding_hint.encoded_length();
        len += self.unknown_tlvs[3].len();
        len += self.nonce.encoded_length();
        len += self.unknown_tlvs[4].len();
        len += self.interest_lifetime.encoded_length();
        len += self.unknown_tlvs[5].len();
        len += (HopLimit::TLV_TYPE as u64).encoded_length() + 1; // only adding T and L for hop limit

        Some(len)
    }
}

impl<'a> TlvEncode for Interest<'a> {
    const TLV_TYPE: u32 = 5;

    fn inner_length(&self) -> usize {
        let mut len = self.name.encoded_length();
        len += self.unknown_tlvs[0].len();
        len += self.can_be_prefix.encoded_length();
        len += self.unknown_tlvs[1].len();
        len += self.must_be_fresh.encoded_length();
        len += self.unknown_tlvs[2].len();
        len += self.forwarding_hint.encoded_length();
        len += self.unknown_tlvs[3].len();
        len += self.nonce.encoded_length();
        len += self.unknown_tlvs[4].len();
        len += self.interest_lifetime.encoded_length();
        len += self.unknown_tlvs[5].len();
        len += self.hop_limit.encoded_length();
        len += self.unknown_tlvs[6].len();
        len += self.application_parameters.encoded_length();
        len
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.name.encode(writer)?;
        writer.write(self.unknown_tlvs[0])?;
        self.can_be_prefix.encode(writer)?;
        writer.write(self.unknown_tlvs[1])?;
        self.must_be_fresh.encode(writer)?;
        writer.write(self.unknown_tlvs[2])?;
        self.forwarding_hint.encode(writer)?;
        writer.write(self.unknown_tlvs[3])?;
        self.nonce.encode(writer)?;
        writer.write(self.unknown_tlvs[4])?;
        self.interest_lifetime.encode(writer)?;
        writer.write(self.unknown_tlvs[5])?;
        self.hop_limit.encode(writer)?;
        writer.write(self.unknown_tlvs[6])?;
        self.application_parameters.encode(writer)
    }
}

pub type CanBePrefix = TypedEmpty<33>;
pub type MustBeFresh = TypedEmpty<18>;
pub type ForwardingHint<'a> = TypedBytes<'a, 30>;
pub type InterestNonce = TypedArray<10, 4>;
pub type InterestLifetime = TypedInteger<12, u64>;
pub type HopLimit = TypedInteger<34, u8>;

pub struct Data<'a> {
    pub name: Name<'a>,
    pub meta_info: Option<MetaInfo<'a>>,
    pub content: Option<Content<'a>>,
    pub signature_info: SignatureInfo<'a>,
    pub signature_value: SignatureValue<'a>,

    // The specification allows for any number of TLVs that are not currently known,
    //  but that should still be preserved.
    // If any unknown TLV has a critical type, we must stop procesing the packet.
    // To avoid allocations we keep an array of pointers to _possible_ places
    //  where zero or more unknown TLVs might happen. We store them as slices.
    // They cannot occur before name or after the signature.
    pub unknown_tlvs: [&'a [u8]; 3],
}

impl<'a> Data<'a> {
    pub fn new_unsigned(
        name: Name<'a>,
        payload: &'a [u8],
        signature_info: SignatureInfo<'a>,
    ) -> Self {
        Self {
            name,
            meta_info: None,
            content: Some(Content { bytes: payload }),
            signature_info,
            signature_value: SignatureValue { bytes: &[] },
            unknown_tlvs: Default::default(),
        }
    }

    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut offset = 0;

        let (name_tlv, name_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
        if name_tlv.typ.get() != Name::TLV_TYPE {
            return None; // Name must be the first TLV
        }
        offset += name_len;
        let name = Name::try_decode(name_tlv.val)?;

        // The rest should typically be a few known TLVs in order,
        //  but they may contain arbitrary non-critical TLVs too.
        // We store those as byte ranges each of which can contain zero or more TLVs.
        let mut meta_info = None;
        let mut content = None;
        let mut signature_info = None;
        let mut signature_value = None;
        let mut unknown_tlv_ranges = [(0usize, 0usize); 3];

        let known = [
            MetaInfo::TLV_TYPE,
            Content::TLV_TYPE,
            SignatureInfo::TLV_TYPE,
            SignatureValue::TLV_TYPE,
        ];
        let mut minimum_possible_known = 0;

        while offset < inner_bytes.len() {
            let (tlv, tlv_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            let typ = tlv.typ.get();
            if let Some(idx) = known.iter().position(|x| &typ == x) {
                // It is one of the known and expected TLVs
                if idx < minimum_possible_known {
                    return None; // ...but the order of known elements is incorrect
                }

                match idx {
                    0 => meta_info = Some(MetaInfo::try_decode(tlv.val)?),
                    1 => content = Some(Content { bytes: tlv.val }),
                    2 => signature_info = Some(SignatureInfo::try_decode(tlv.val)?),
                    3 => signature_value = Some(SignatureValue { bytes: tlv.val }),
                    _ => unreachable!(),
                }
                minimum_possible_known = idx;
            } else {
                // It is an unknown TLV
                if tlv.type_is_critical() {
                    return None; // There is a critical unknown type, so we must bail
                }

                // Check if we already have something in this range
                if unknown_tlv_ranges[minimum_possible_known] == (0, 0) {
                    unknown_tlv_ranges[minimum_possible_known] = (offset, offset + tlv_len)
                } else {
                    debug_assert!(unknown_tlv_ranges[minimum_possible_known].1 == offset);
                    unknown_tlv_ranges[minimum_possible_known].1 += tlv_len;
                }
            }

            offset += tlv_len;
        }

        let signature_info = signature_info?;
        let signature_value = signature_value?;
        let unknown_tlvs = unknown_tlv_ranges.map(|(b, e)| &inner_bytes[b..e]);

        Some(Data {
            name,
            meta_info,
            content,
            signature_info,
            signature_value,
            unknown_tlvs,
        })
    }

    // This captures the range of everything from the beginning of name and up to
    //  the end of signature_info. It does not cover the top-level "Data packet" TLV.
    // We do not keep the reference to the buffer as it only applies to the original.
    fn length_of_signed_portion(&self) -> usize {
        let mut len = self.name.encoded_length();
        len += self.unknown_tlvs[0].len();
        len += self.meta_info.encoded_length();
        len += self.unknown_tlvs[1].len();
        len += self.content.encoded_length();
        len += self.unknown_tlvs[2].len();
        len + self.signature_info.encoded_length()
    }

    pub fn hash_signed_portion<H: Hasher>(&self, hasher: &mut H) {
        let mut hh = EncodedHasher { hasher };
        let _ = self.encode_signed_portion(&mut hh);
    }

    fn encode_signed_portion<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.name.encode(writer)?;
        writer.write(self.unknown_tlvs[0])?;
        self.meta_info.encode(writer)?;
        writer.write(self.unknown_tlvs[1])?;
        self.content.encode(writer)?;
        writer.write(self.unknown_tlvs[2])?;
        self.signature_info.encode(writer)
    }
}

impl<'a> TlvEncode for Data<'a> {
    const TLV_TYPE: u32 = 6;

    fn inner_length(&self) -> usize {
        self.length_of_signed_portion() + self.signature_value.encoded_length()
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.encode_signed_portion(writer)?;
        self.signature_value.encode(writer)
    }
}

pub type Content<'a> = TypedBytes<'a, 21>;

pub type ApplicationParameters<'a> = TypedBytes<'a, 36>;

pub struct MetaInfo<'a> {
    pub content_type: Option<ContentType>,
    pub freshness_period: Option<FreshnessPeriod>,
    pub final_block_id: Option<FinalBlockId<'a>>,
    pub unknown_tlvs: &'a [u8], // Allow arbitrary TLVs after the original ones
}

impl<'a> MetaInfo<'a> {
    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut content_type = None;
        let mut freshness_period = None;
        let mut final_block_id = None;
        let mut unknown_tlv_range: Option<(usize, usize)> = None;

        let mut offset = 0;
        while offset < inner_bytes.len() {
            let (inner_tlv, inner_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            match inner_tlv.typ.get() {
                ContentType::TLV_TYPE => {
                    if unknown_tlv_range.is_some() {
                        return None;
                    }
                    content_type = Some(ContentType {
                        val: inner_tlv.val_as_u64()?,
                    })
                }
                FreshnessPeriod::TLV_TYPE => {
                    if unknown_tlv_range.is_some() {
                        return None;
                    }
                    freshness_period = Some(FreshnessPeriod {
                        val: inner_tlv.val_as_u64()?,
                    })
                }
                FinalBlockId::TLV_TYPE => {
                    if unknown_tlv_range.is_some() {
                        return None;
                    }
                    final_block_id = Some(FinalBlockId::try_decode(inner_tlv.val)?)
                }
                _ => match &mut unknown_tlv_range {
                    Some(unknown_tlv_range) => (*unknown_tlv_range).1 += inner_len,
                    None => unknown_tlv_range = Some((offset, offset + inner_len)),
                },
            }
            offset += inner_len;
        }

        let unknown_tlvs = match unknown_tlv_range {
            Some((b, e)) => &inner_bytes[b..e],
            None => &[],
        };

        Some(MetaInfo {
            content_type,
            freshness_period,
            final_block_id,
            unknown_tlvs,
        })
    }
}

impl<'a> TlvEncode for MetaInfo<'a> {
    const TLV_TYPE: u32 = 20;

    fn inner_length(&self) -> usize {
        let mut len = 0;
        len += self.content_type.encoded_length();
        len += self.freshness_period.encoded_length();
        len += self.final_block_id.encoded_length();
        len + self.unknown_tlvs.len()
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.content_type.encode(writer)?;
        self.freshness_period.encode(writer)?;
        self.final_block_id.encode(writer)?;
        writer.write(self.unknown_tlvs)
    }
}

pub type ContentType = TypedInteger<24, u64>;

impl ContentType {
    pub const BLOB: u64 = 0;
    pub const KEY: u64 = 1;
    pub const LINK: u64 = 2;
    pub const NACK: u64 = 3;
}

pub type FreshnessPeriod = TypedInteger<25, u64>;

#[derive(Clone, Copy)]
pub struct FinalBlockId<'a> {
    pub component: NameComponent<'a>,
}

impl<'a> FinalBlockId<'a> {
    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        if let Ok((nc_tlv, _)) = TLV::try_decode(inner_bytes) {
            let typ: NonZeroU16 = nc_tlv.typ.try_into().ok()?;
            Some(FinalBlockId {
                component: NameComponent {
                    typ,
                    bytes: nc_tlv.val,
                },
            })
        } else {
            None
        }
    }
}

impl<'a> TlvEncode for FinalBlockId<'a> {
    const TLV_TYPE: u32 = 26;

    fn inner_length(&self) -> usize {
        self.component.encoded_length()
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.component.encode(writer)
    }
}

pub struct SignatureInfo<'a> {
    pub signature_type: SignatureType,
    pub key_locator: Option<KeyLocator<'a>>,
}

impl<'a> SignatureInfo<'a> {
    pub fn new_digest_sha256() -> Self {
        Self {
            signature_type: TypedInteger {
                val: SignatureType::DIGEST_SHA256,
            },
            key_locator: None,
        }
    }

    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut offset = 0;
        let (signature_type_tlv, sig_type_len) = TLV::try_decode(inner_bytes).ok()?;
        if signature_type_tlv.typ.get() != SignatureType::TLV_TYPE {
            return None;
        }
        offset += sig_type_len;
        let signature_type = SignatureType {
            val: signature_type_tlv.val_as_u64()?,
        };

        let mut key_locator = None;

        if let Ok((key_locator_tlv, _)) = TLV::try_decode(&inner_bytes[offset..]) {
            if key_locator_tlv.typ.get() == KeyLocator::TLV_TYPE {
                key_locator = Some(KeyLocator::try_decode(key_locator_tlv.val)?)
            }
        }

        Some(Self {
            signature_type,
            key_locator,
        })
    }
}

impl<'a> TlvEncode for SignatureInfo<'a> {
    const TLV_TYPE: u32 = 22;

    fn inner_length(&self) -> usize {
        let mut len = self.signature_type.encoded_length();
        len += self.key_locator.encoded_length();
        len
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.signature_type.encode(writer)?;
        self.key_locator.encode(writer)?;
        Ok(())
    }
}

pub type SignatureType = TypedInteger<27, u64>;

impl SignatureType {
    pub const DIGEST_SHA256: u64 = 0;
    pub const SHA256_RSA: u64 = 1;
    pub const SHA256_ECDSA: u64 = 3;
    pub const HMAC_SHA256: u64 = 4;
    pub const ED25519: u64 = 5;
}

pub type SignatureValue<'a> = TypedBytes<'a, 23>;

pub struct InterestSignatureInfo<'a> {
    pub signature_type: SignatureType,
    pub key_locator: Option<KeyLocator<'a>>,
    pub nonce: Option<InterestSignatureNonce<'a>>,
    pub signature_time: Option<InterestSignatureTime>,
    pub signature_seq_num: Option<InterestSignatureSeqNum>,
}

impl<'a> InterestSignatureInfo<'a> {
    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut offset = 0;
        let (signature_type_tlv, sig_type_len) = TLV::try_decode(inner_bytes).ok()?;
        if signature_type_tlv.typ.get() != SignatureType::TLV_TYPE {
            return None;
        }
        offset += sig_type_len;
        let signature_type = SignatureType {
            val: signature_type_tlv.val_as_u64()?,
        };

        let mut key_locator = None;
        let mut nonce = None;
        let mut signature_time = None;
        let mut signature_seq_num = None;

        while offset < inner_bytes.len() {
            let (tlv, tlv_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            match tlv.typ.get() {
                KeyLocator::TLV_TYPE => key_locator = Some(KeyLocator::try_decode(tlv.val)?),
                InterestSignatureNonce::TLV_TYPE => {
                    nonce = Some(InterestSignatureNonce { bytes: tlv.val })
                }
                InterestSignatureTime::TLV_TYPE => {
                    signature_time = Some(InterestSignatureTime {
                        val: tlv.val_as_u64()?,
                    })
                }
                InterestSignatureSeqNum::TLV_TYPE => {
                    signature_seq_num = Some(InterestSignatureSeqNum {
                        val: tlv.val_as_u64()?,
                    })
                }
                _ => return None,
            }
            offset += tlv_len;
        }

        Some(Self {
            signature_type,
            key_locator,
            nonce,
            signature_time,
            signature_seq_num,
        })
    }
}

impl<'a> TlvEncode for InterestSignatureInfo<'a> {
    const TLV_TYPE: u32 = 44;

    fn inner_length(&self) -> usize {
        let mut len = self.signature_type.encoded_length();
        len += self.key_locator.encoded_length();
        len += self.nonce.encoded_length();
        len += self.signature_time.encoded_length();
        len += self.signature_seq_num.encoded_length();
        len
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.signature_type.encode(writer)?;
        self.key_locator.encode(writer)?;
        self.nonce.encode(writer)?;
        self.signature_time.encode(writer)?;
        self.signature_seq_num.encode(writer)
    }
}

pub type InterestSignatureNonce<'a> = TypedBytes<'a, 38>;
pub type InterestSignatureTime = TypedInteger<40, u64>;
pub type InterestSignatureSeqNum = TypedInteger<42, u64>;
pub type InterestSignatureValue<'a> = TypedBytes<'a, 46>;

pub enum KeyLocator<'a> {
    Name(Name<'a>),
    KeyDigest(KeyDigest<'a>),
}

impl<'a> KeyLocator<'a> {
    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let (inner_tlv, _) = TLV::try_decode(inner_bytes).ok()?;
        match inner_tlv.typ.get() {
            Name::TLV_TYPE => Some(Self::Name(Name::try_decode(inner_tlv.val)?)),
            KeyDigest::TLV_TYPE => Some(Self::KeyDigest(KeyDigest {
                bytes: &inner_tlv.val,
            })),
            _ => None,
        }
    }
}

impl<'a> TlvEncode for KeyLocator<'a> {
    const TLV_TYPE: u32 = 28;

    fn inner_length(&self) -> usize {
        match self {
            KeyLocator::Name(name) => name.encoded_length(),
            KeyLocator::KeyDigest(locator) => locator.encoded_length(),
        }
    }

    fn encode_inner<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        match self {
            KeyLocator::Name(name) => name.encode(writer),
            KeyLocator::KeyDigest(locator) => locator.encode(writer),
        }
    }
}

pub type KeyDigest<'a> = TypedBytes<'a, 29>;

struct EncodedHasher<'a, H: Hasher> {
    hasher: &'a mut H,
}

impl<'a, H: Hasher> crate::io::Write for EncodedHasher<'a, H> {
    type Error = ();

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        Ok(self.hasher.update(bytes))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{packet::KeyLocator, tlv::Encode};

    #[test]
    fn test_key_locator() {
        let name_locator_inner_bytes = &[
            7, 14, 8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd',
        ];

        let name_locator_outer_bytes = &[
            29, 16, 7, 14, 8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd',
        ];

        let name_locator = KeyLocator::try_decode(name_locator_inner_bytes);
        assert!(name_locator.is_some());
        let name = match &name_locator {
            Some(KeyLocator::Name(name)) => name,
            _ => panic!(),
        };
        assert!(name.component_count() == 2);

        let mut buf = Vec::new();
        let name_locator = name_locator.unwrap();
        assert!(name_locator.encoded_length() == name_locator_outer_bytes.len());
        let _ = name_locator.encode(&mut buf);
        assert!(buf.as_slice() == name_locator_outer_bytes);

        let name_locator = KeyLocator::try_decode(&[
            7, 15, 8, 5, b'h', b'e', b'l', b'l', b'o', 1, 5, b'w', b'o', b'r', b'l', b'd',
        ]);
        assert!(name_locator.is_none());

        let name_locator = KeyLocator::try_decode(&[
            7, 15, 8, 5, b'h', b'e', b'l', b'l', b'o', 1, 6, b'w', b'o', b'r', b'l', b'd',
        ]);
        assert!(name_locator.is_none());

        let digest_locator_inner_bytes = &[28, 4, 255, 254, 253, 252];

        let digest_locator_outer_bytes = &[29, 6, 28, 4, 255, 254, 253, 252];

        let digest_locator = KeyLocator::try_decode(digest_locator_inner_bytes);
        assert!(digest_locator.is_some());
        let digest = match &digest_locator {
            Some(KeyLocator::KeyDigest(digest)) => digest,
            _ => panic!(),
        };
        assert!(digest.bytes == &[255, 254, 253, 252]);

        let mut buf = Vec::new();
        let digest_locator = digest_locator.unwrap();
        assert!(digest_locator.encoded_length() == digest_locator_outer_bytes.len());
        let _ = digest_locator.encode(&mut buf);
        assert!(buf.as_slice() == digest_locator_outer_bytes);
    }

    #[test]
    fn test_signature_info() {}

    #[test]
    fn test_interest_signature_info() {}

    #[test]
    fn test_meta_info() {}

    #[test]
    fn test_application_parameters() {}

    #[test]
    fn test_data() {
        // Including hashing
    }

    #[test]
    fn test_interest() {
        // Including hashing
        // Including hop byte
    }
}
