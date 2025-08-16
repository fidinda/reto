use crate::{
    hash::Hasher,
    io::Write,
    name::{Name, NameComponent},
    tlv::{Encode, TLV},
};
use core::num::NonZeroU16;

pub struct Interest<'a> {
    pub name: Name<'a>,
    pub can_be_prefix: bool,
    pub must_be_fresh: bool,
    pub forwarding_hint: Option<&'a [u8]>,
    pub nonce: Option<[u8; 4]>,
    pub interest_lifetime: Option<u64>,
    pub hop_limit: Option<u8>,
    pub application_parameters: Option<ApplicationParameters<'a>>,

    // The specification allows for any number of TLVs that are not currently known,
    //  but that should still be preserved.
    // If any unknown TLV has a critical type, we must stop procesing the packet.
    // To avoid allocations we keep an array of pointers to _possible_ places
    //  where zero or more unknown TLVs might happen. We store them as slices.
    // They cannot occur before name or after the signature.
    pub unknown_tlvs: [&'a [u8]; 7],
}

impl<'a> Interest<'a> {
    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut offset = 0;

        let (name_tlv, name_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
        if name_tlv.typ.get() != Name::TLV_TYPE_NAME {
            return None; // Name must be the first TLV
        }
        offset += name_len;
        let name = Name::try_decode(name_tlv.val)?;

        // The rest should typically be a few known TLVs in order,
        //  but they may contain arbitrary non-critical TLVs too.
        // We store those as byte ranges each of which can contain zero or more TLVs.
        let mut can_be_prefix = false;
        let mut must_be_fresh = false;
        let mut forwarding_hint = None;
        let mut nonce = None;
        let mut interest_lifetime = None;
        let mut hop_limit = None;
        let mut application_parameters = None;
        let mut unknown_tlv_ranges = [(0usize, 0usize); 7];

        let known = [
            TLV_TYPE_CAN_BE_PREFIX,
            TLV_TYPE_MUST_BE_FRESH,
            TLV_TYPE_FORWARDING_HINT,
            TLV_TYPE_NONCE,
            TLV_TYPE_INTEREST_LIFETIME,
            TLV_TYPE_HOP_LIMIT,
            TLV_TYPE_APPLICATION_PARAMETERS,
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
                    0 => can_be_prefix = true,
                    1 => must_be_fresh = true,
                    2 => forwarding_hint = Some(tlv.val),
                    3 => nonce = Some(tlv.val.try_into().ok()?),
                    4 => interest_lifetime = Some(tlv.val_as_u64()?),
                    5 => hop_limit = Some(tlv.val_as_u64()? as u8),
                    6 => application_parameters = Some(ApplicationParameters::try_decode(tlv.val)?),
                    _ => unreachable!(),
                }
                minimum_possible_known = idx;
            } else {
                // It is an unknown TLV
                if tlv.is_critical() {
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

    pub fn hash_signed_portion<const N: usize, H: Hasher<N>>(&self, hasher: &mut H) {
        let mut relevant_name = self.name;
        if let Some(last_component) = relevant_name.components().last() {
            if last_component.typ.get() == NameComponent::TYPE_PARAMETER_SHA256 {
                relevant_name = relevant_name.dropping_last_component().unwrap();
            }
        }

        let mut hh = crate::hash::EncodedHasher { hasher };
        let _ = relevant_name.encode(&mut hh);
    }

    pub(crate) fn index_of_hop_byte_in_encoded_tlv(&self) -> Option<usize> {
        todo!()
    }
}

impl<'a> Encode for Interest<'a> {
    fn encoded_length(&self) -> usize {
        let mut len = self.name.encoded_length();
        len += self.unknown_tlvs[0].len();
        if self.can_be_prefix {
            len += (TLV_TYPE_CAN_BE_PREFIX as u64).encoded_length() + 0u64.encoded_length();
        }
        len += self.unknown_tlvs[1].len();
        if self.must_be_fresh {
            len += (TLV_TYPE_MUST_BE_FRESH as u64).encoded_length() + 0u64.encoded_length();
        }
        len += self.unknown_tlvs[2].len();
        if let Some(forwarding_hint) = &self.forwarding_hint {
            len += (TLV_TYPE_FORWARDING_HINT as u64).encoded_length()
                + (forwarding_hint.len() as u64).encoded_length()
                + forwarding_hint.len();
        }
        len += self.unknown_tlvs[3].len();
        if let Some(nonce) = &self.nonce {
            len += (TLV_TYPE_NONCE as u64).encoded_length()
                + (nonce.len() as u64).encoded_length()
                + nonce.len();
        }
        len += self.unknown_tlvs[4].len();
        if let Some(interest_lifetime) = &self.interest_lifetime {
            len += (TLV_TYPE_INTEREST_LIFETIME as u64).encoded_length()
                + interest_lifetime.encoded_length();
        }
        len += self.unknown_tlvs[5].len();
        if let Some(_hop_limit) = &self.hop_limit {
            len += (TLV_TYPE_HOP_LIMIT as u64).encoded_length() + 1 + 1;
        }
        len += self.unknown_tlvs[6].len();
        if let Some(application_parameters) = &self.application_parameters {
            len += application_parameters.encoded_length();
        }
        (TLV_TYPE_INTEREST as u64).encoded_length() + (len as u64).encoded_length() + len
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        let len = self.encoded_length();
        (TLV_TYPE_INTEREST as u64).encode(writer)?;
        (len as u64).encode(writer)?;
        self.name.encode(writer)?;
        writer.write(self.unknown_tlvs[0])?;
        if self.can_be_prefix {
            (TLV_TYPE_CAN_BE_PREFIX as u64).encode(writer)?;
            0u64.encode(writer)?;
        }
        writer.write(self.unknown_tlvs[1])?;
        if self.must_be_fresh {
            (TLV_TYPE_MUST_BE_FRESH as u64).encode(writer)?;
            0u64.encode(writer)?;
        }
        writer.write(self.unknown_tlvs[2])?;
        if let Some(forwarding_hint) = &self.forwarding_hint {
            (TLV_TYPE_FORWARDING_HINT as u64).encode(writer)?;
            (forwarding_hint.len() as u64).encode(writer)?;
            writer.write(forwarding_hint)?;
        }
        writer.write(self.unknown_tlvs[3])?;
        if let Some(nonce) = &self.nonce {
            (TLV_TYPE_NONCE as u64).encode(writer)?;
            (nonce.len() as u64).encode(writer)?;
            writer.write(nonce)?;
        }
        writer.write(self.unknown_tlvs[4])?;
        if let Some(interest_lifetime) = &self.interest_lifetime {
            (TLV_TYPE_INTEREST_LIFETIME as u64).encode(writer)?;
            interest_lifetime.encode(writer)?;
        }
        writer.write(self.unknown_tlvs[5])?;
        if let Some(hop_limit) = &self.hop_limit {
            (TLV_TYPE_HOP_LIMIT as u64).encode(writer)?;
            1u64.encode(writer)?;
            (*hop_limit as u64).encode(writer)?;
        }
        writer.write(self.unknown_tlvs[6])?;
        if let Some(application_parameters) = &self.application_parameters {
            application_parameters.encode(writer)?;
        }
        Ok(())
    }
}

pub struct Data<'a> {
    pub name: Name<'a>,
    pub meta_info: Option<MetaInfo<'a>>,
    pub content: Option<&'a [u8]>,
    pub signature_info: SignatureInfo<'a>,
    pub signature_value: &'a [u8],

    // The specification allows for any number of TLVs that are not currently known,
    //  but that should still be preserved.
    // If any unknown TLV has a critical type, we must stop procesing the packet.
    // To avoid allocations we keep an array of pointers to _possible_ places
    //  where zero or more unknown TLVs might happen. We store them as slices.
    // They cannot occur before name or after the signature.
    pub unknown_tlvs: [&'a [u8]; 3],
}

impl<'a> Data<'a> {
    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut offset = 0;

        let (name_tlv, name_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
        if name_tlv.typ.get() != Name::TLV_TYPE_NAME {
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
            TLV_TYPE_META_INFO,
            TLV_TYPE_CONTENT,
            TLV_TYPE_SIGNATURE_INFO,
            TLV_TYPE_SIGNATURE_VALUE,
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
                    1 => content = Some(tlv.val),
                    2 => signature_info = Some(SignatureInfo::try_decode(tlv.val)?),
                    3 => signature_value = Some(tlv.val),
                    _ => unreachable!(),
                }
                minimum_possible_known = idx;
            } else {
                // It is an unknown TLV
                if tlv.is_critical() {
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
        if let Some(meta_info) = &self.meta_info {
            len += meta_info.encoded_length();
        }
        len += self.unknown_tlvs[1].len();
        if let Some(content) = &self.content {
            (TLV_TYPE_CONTENT as u64).encoded_length();
            (content.len() as u64).encoded_length();
            len += content.len();
        }
        len += self.unknown_tlvs[2].len();
        len + self.signature_info.encoded_length()
    }

    pub fn hash_signed_portion<const N: usize, H: Hasher<N>>(&self, hasher: &mut H) {
        let mut hh = crate::hash::EncodedHasher { hasher };
        let _ = self.encode_signed_portion(&mut hh);
    }

    fn encode_signed_portion<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        self.name.encode(writer)?;
        writer.write(self.unknown_tlvs[0])?;
        if let Some(meta_info) = &self.meta_info {
            meta_info.encode(writer)?;
        }
        writer.write(self.unknown_tlvs[1])?;
        if let Some(content) = &self.content {
            (TLV_TYPE_CONTENT as u64).encode(writer)?;
            (content.len() as u64).encode(writer)?;
            writer.write(content)?;
        }
        writer.write(self.unknown_tlvs[2])?;
        self.signature_info.encode(writer)
    }
}

impl<'a> Encode for Data<'a> {
    fn encoded_length(&self) -> usize {
        let mut len = self.length_of_signed_portion();
        len += (TLV_TYPE_SIGNATURE_VALUE as u64).encoded_length();
        (self.signature_value.len() as u64).encoded_length();
        len += self.signature_value.len();
        (TLV_TYPE_DATA as u64).encoded_length() + (len as u64).encoded_length() + len
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        let len = self.encoded_length();
        (TLV_TYPE_DATA as u64).encode(writer)?;
        (len as u64).encode(writer)?;
        self.encode_signed_portion(writer)?;
        (TLV_TYPE_SIGNATURE_VALUE as u64).encode(writer)?;
        (self.signature_value.len() as u64).encode(writer)?;
        writer.write(self.signature_value)
    }
}

pub struct ApplicationParameters<'a> {
    pub payload: &'a [u8],
    pub signature: Option<(InterestSignatureInfo<'a>, &'a [u8])>,
}

impl<'a> ApplicationParameters<'a> {
    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let (inner_tlv, inner_len) = TLV::try_decode(inner_bytes).ok()?;
        if inner_tlv.typ.get() != TLV_TYPE_APPLICATION_PARAMETERS {
            return None;
        }
        let payload = inner_tlv.val;
        let mut signature = None;
        if inner_len < inner_bytes.len() {
            let mut offset = inner_len;
            let (si_tlv, si_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            if si_tlv.typ.get() != TLV_TYPE_INTEREST_SIGNATURE_INFO {
                return None;
            }
            let si = InterestSignatureInfo::try_decode(si_tlv.val)?;
            offset += si_len;
            let (sv_tlv, sv_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            if sv_tlv.typ.get() != TLV_TYPE_INTEREST_SIGNATURE_VALUE {
                return None;
            }
            if offset + sv_len != inner_bytes.len() {
                return None;
            }
            signature = Some((si, si_tlv.val))
        }

        Some(Self { payload, signature })
    }

    pub fn hash_signed_portion<const N: usize, H: Hasher<N>>(&self, hasher: &mut H) {
        let signature_info = match &self.signature {
            Some((signature_info, _)) => signature_info,
            None => return,
        };

        let mut hh = crate::hash::EncodedHasher { hasher };
        let _ = (TLV_TYPE_APPLICATION_PARAMETERS as u64).encode(&mut hh);
        let _ = (self.payload.len() as u64).encode(&mut hh);
        let _ = hh.write(self.payload);
        let _ = signature_info.encode(&mut hh);
    }
}

impl<'a> Encode for ApplicationParameters<'a> {
    fn encoded_length(&self) -> usize {
        let mut len = (TLV_TYPE_APPLICATION_PARAMETERS as u64).encoded_length()
            + (self.payload.len() as u64).encoded_length()
            + self.payload.len();

        if let Some(signature) = &self.signature {
            len += signature.0.encoded_length();
            len += (TLV_TYPE_INTEREST_SIGNATURE_VALUE as u64).encoded_length()
                + (signature.1.len() as u64).encoded_length()
                + signature.1.len();
        }

        len
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        (TLV_TYPE_APPLICATION_PARAMETERS as u64).encode(writer)?;
        (self.payload.len() as u64).encode(writer)?;
        writer.write(self.payload)?;
        if let Some(signature) = &self.signature {
            signature.0.encode(writer)?;
            (TLV_TYPE_INTEREST_SIGNATURE_VALUE as u64).encode(writer)?;
            (signature.1.len() as u64).encode(writer)?;
            writer.write(signature.1)?;
        }
        Ok(())
    }
}

pub struct MetaInfo<'a> {
    pub content_type: Option<u64>,
    pub freshness_period: Option<u64>,
    pub final_block_id: Option<NameComponent<'a>>,
    pub unknown_tlvs: &'a [u8], // Allow arbitrary TLVs after the original ones
}

impl<'a> MetaInfo<'a> {
    pub const CONTENT_TYPE_BLOB: u64 = 0;
    pub const CONTENT_TYPE_KEY: u64 = 1;
    pub const CONTENT_TYPE_LINK: u64 = 2;
    pub const CONTENT_TYPE_NACK: u64 = 3;

    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut content_type = None;
        let mut freshness_period = None;
        let mut final_block_id = None;
        let mut unknown_tlv_range: Option<(usize, usize)> = None;

        let mut offset = 0;
        while offset < inner_bytes.len() {
            let (inner_tlv, inner_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            match inner_tlv.typ.get() {
                TLV_TYPE_META_INFO_CONTENT_TYPE => {
                    if unknown_tlv_range.is_some() {
                        return None;
                    }
                    content_type = Some(inner_tlv.val_as_u64()?.into())
                }
                TLV_TYPE_META_INFO_FRESHNESS_PERIOD => {
                    if unknown_tlv_range.is_some() {
                        return None;
                    }
                    freshness_period = Some(inner_tlv.val_as_u64()?)
                }
                TLV_TYPE_META_INFO_FINAL_BLOCK_ID => {
                    if unknown_tlv_range.is_some() {
                        return None;
                    }
                    if let Ok((nc_tlv, _)) = TLV::try_decode(inner_tlv.val) {
                        let typ: NonZeroU16 = nc_tlv.typ.try_into().ok()?;
                        final_block_id = Some(NameComponent {
                            typ,
                            bytes: nc_tlv.val,
                        })
                    }
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

impl<'a> Encode for MetaInfo<'a> {
    fn encoded_length(&self) -> usize {
        let mut len = 0;
        if let Some(ct) = self.content_type {
            let ct: u64 = ct.into();
            let ctl = ct.encoded_length();
            len += (TLV_TYPE_META_INFO_CONTENT_TYPE as u64).encoded_length();
            len += (ctl as u64).encoded_length();
            len += ct.encoded_length();
        }
        if let Some(freshness_period) = self.freshness_period {
            len += (TLV_TYPE_META_INFO_FRESHNESS_PERIOD as u64).encoded_length();
            len += (freshness_period as u64).encoded_length();
            len += freshness_period.encoded_length();
        }
        if let Some(final_block_id) = self.final_block_id {
            let tlv = TLV {
                typ: final_block_id.typ.into(),
                val: final_block_id.bytes,
            };
            let nc_len = tlv.encoded_length();
            len += (TLV_TYPE_META_INFO_FINAL_BLOCK_ID as u64).encoded_length()
                + (nc_len as u64).encoded_length()
                + nc_len;
        }
        len + self.unknown_tlvs.len()
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        (TLV_TYPE_META_INFO as u64).encode(writer)?;
        let encoded_len = self.encoded_length();
        (encoded_len as u64).encode(writer)?;
        if let Some(ct) = self.content_type {
            (TLV_TYPE_META_INFO_CONTENT_TYPE as u64).encode(writer)?;
            let ct: u64 = ct.into();
            (ct.encoded_length() as u64).encode(writer)?;
            ct.encode(writer)?;
        }
        if let Some(freshness_period) = self.freshness_period {
            (TLV_TYPE_META_INFO_FRESHNESS_PERIOD as u64).encode(writer)?;
            (freshness_period.encoded_length() as u64).encode(writer)?;
            freshness_period.encode(writer)?;
        }
        if let Some(final_block_id) = self.final_block_id {
            let tlv = TLV {
                typ: final_block_id.typ.into(),
                val: final_block_id.bytes,
            };
            let nc_len = tlv.encoded_length();
            (TLV_TYPE_META_INFO_FINAL_BLOCK_ID as u64).encode(writer)?;
            (nc_len as u64).encode(writer)?;
            tlv.encode(writer)?;
        }
        writer.write(self.unknown_tlvs)
    }
}

pub struct SignatureInfo<'a> {
    pub signature_type: u64,
    pub key_locator: Option<KeyLocator<'a>>,
}

impl<'a> SignatureInfo<'a> {
    pub const SIGNATURE_TYPE_DIGEST_SHA256: u64 = 0;
    pub const SIGNATURE_TYPE_SHA256_RSA: u64 = 1;
    pub const SIGNATURE_TYPE_SHA256_ECDSA: u64 = 3;
    pub const SIGNATURE_TYPE_HMAC_SHA256: u64 = 4;
    pub const SIGNATURE_TYPE_ED25519: u64 = 5;

    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut offset = 0;
        let (signature_type_tlv, sig_type_len) = TLV::try_decode(inner_bytes).ok()?;
        if signature_type_tlv.typ.get() != TLV_TYPE_SIGNATURE_TYPE {
            return None;
        }
        offset += sig_type_len;
        let signature_type = signature_type_tlv.val_as_u64()?.into();

        let mut key_locator = None;

        if let Ok((key_locator_tlv, _)) = TLV::try_decode(&inner_bytes[offset..]) {
            if key_locator_tlv.typ.get() == TLV_TYPE_SIGNATURE_KEY_LOCATOR {
                key_locator = Some(KeyLocator::try_decode(key_locator_tlv.val)?)
            }
        }

        Some(Self {
            signature_type,
            key_locator,
        })
    }
}

impl<'a> Encode for SignatureInfo<'a> {
    fn encoded_length(&self) -> usize {
        let mut len = (TLV_TYPE_SIGNATURE_TYPE as u64).encoded_length()
            + self.signature_type.encoded_length();
        if let Some(key_locator) = &self.key_locator {
            len += key_locator.encoded_length();
        }
        (TLV_TYPE_SIGNATURE_INFO as u64).encoded_length() + (len as u64).encoded_length() + len
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        let len = self.encoded_length();
        (TLV_TYPE_SIGNATURE_INFO as u64).encode(writer)?;
        (len as u64).encode(writer)?;
        (TLV_TYPE_SIGNATURE_TYPE as u64).encode(writer)?;
        self.signature_type.encode(writer)?;
        if let Some(key_locator) = &self.key_locator {
            key_locator.encode(writer)?;
        }
        Ok(())
    }
}

pub struct InterestSignatureInfo<'a> {
    pub signature_type: u64,
    pub key_locator: Option<KeyLocator<'a>>,
    pub nonce: Option<&'a [u8]>,
    pub signature_time: Option<u64>,
    pub signature_seq_num: Option<u64>,
}

impl<'a> InterestSignatureInfo<'a> {
    pub const SIGNATURE_TYPE_DIGEST_SHA256: u64 = 0;
    pub const SIGNATURE_TYPE_SHA256_RSA: u64 = 1;
    pub const SIGNATURE_TYPE_SHA256_ECDSA: u64 = 3;
    pub const SIGNATURE_TYPE_HMAC_SHA256: u64 = 4;
    pub const SIGNATURE_TYPE_ED25519: u64 = 5;

    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let mut offset = 0;
        let (signature_type_tlv, sig_type_len) = TLV::try_decode(inner_bytes).ok()?;
        if signature_type_tlv.typ.get() != TLV_TYPE_SIGNATURE_TYPE {
            return None;
        }
        offset += sig_type_len;
        let signature_type = signature_type_tlv.val_as_u64()?.into();

        let mut key_locator = None;
        let mut nonce = None;
        let mut signature_time = None;
        let mut signature_seq_num = None;

        while offset < inner_bytes.len() {
            let (tlv, tlv_len) = TLV::try_decode(&inner_bytes[offset..]).ok()?;
            match tlv.typ.get() {
                TLV_TYPE_SIGNATURE_KEY_LOCATOR => {
                    key_locator = Some(KeyLocator::try_decode(tlv.val)?)
                }
                TLV_TYPE_SIGNATURE_NONCE => nonce = Some(tlv.val),
                TLV_TYPE_SIGNATURE_TIME => signature_time = Some(tlv.val_as_u64()?),
                TLV_TYPE_SIGNATURE_SEQ_NUM => signature_seq_num = Some(tlv.val_as_u64()?),
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

impl<'a> Encode for InterestSignatureInfo<'a> {
    fn encoded_length(&self) -> usize {
        let mut len = (TLV_TYPE_SIGNATURE_TYPE as u64).encoded_length()
            + self.signature_type.encoded_length();
        if let Some(key_locator) = &self.key_locator {
            len += key_locator.encoded_length();
        }
        if let Some(nonce) = self.nonce {
            len += (TLV_TYPE_SIGNATURE_NONCE as u64).encoded_length()
                + (nonce.len() as u64).encoded_length()
                + nonce.len()
        }
        if let Some(signature_time) = self.signature_time {
            len +=
                (TLV_TYPE_SIGNATURE_TIME as u64).encoded_length() + signature_time.encoded_length()
        }
        if let Some(signature_seq_num) = self.signature_seq_num {
            len += (TLV_TYPE_SIGNATURE_SEQ_NUM as u64).encoded_length()
                + signature_seq_num.encoded_length()
        }
        (TLV_TYPE_INTEREST_SIGNATURE_INFO as u64).encoded_length()
            + (len as u64).encoded_length()
            + len
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        let len = self.encoded_length();
        (TLV_TYPE_INTEREST_SIGNATURE_INFO as u64).encode(writer)?;
        (len as u64).encode(writer)?;
        (TLV_TYPE_SIGNATURE_TYPE as u64).encode(writer)?;
        self.signature_type.encode(writer)?;
        if let Some(key_locator) = &self.key_locator {
            key_locator.encode(writer)?;
        }
        if let Some(nonce) = self.nonce {
            (TLV_TYPE_SIGNATURE_NONCE as u64).encode(writer)?;
            (nonce.len() as u64).encode(writer)?;
            writer.write(nonce)?;
        }
        if let Some(signature_time) = self.signature_time {
            (TLV_TYPE_SIGNATURE_TIME as u64).encode(writer)?;
            signature_time.encode(writer)?;
        }
        if let Some(signature_seq_num) = self.signature_seq_num {
            (TLV_TYPE_SIGNATURE_SEQ_NUM as u64).encode(writer)?;
            signature_seq_num.encode(writer)?;
        }
        Ok(())
    }
}

pub enum KeyLocator<'a> {
    Name(Name<'a>),
    KeyDigest(&'a [u8]),
}

impl<'a> KeyLocator<'a> {
    pub fn try_decode(inner_bytes: &'a [u8]) -> Option<Self> {
        let (inner_tlv, _) = TLV::try_decode(inner_bytes).ok()?;
        match inner_tlv.typ.get() {
            Name::TLV_TYPE_NAME => Some(Self::Name(Name::try_decode(inner_tlv.val)?)),
            TLV_TYPE_SIGNATURE_KEY_DIGEST => Some(Self::KeyDigest(&inner_tlv.val)),
            _ => None,
        }
    }
}

impl<'a> Encode for KeyLocator<'a> {
    fn encoded_length(&self) -> usize {
        let len = match self {
            KeyLocator::Name(name) => name.encoded_length(),
            KeyLocator::KeyDigest(items) => {
                (TLV_TYPE_SIGNATURE_KEY_DIGEST as u64).encoded_length()
                    + (items.len() as u64).encoded_length()
                    + items.len()
            }
        };
        (TLV_TYPE_SIGNATURE_KEY_LOCATOR as u64).encoded_length()
            + (len as u64).encoded_length()
            + len
    }

    fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), W::Error> {
        let len = self.encoded_length();
        (TLV_TYPE_SIGNATURE_KEY_LOCATOR as u64).encode(writer)?;
        (len as u64).encode(writer)?;
        match self {
            KeyLocator::Name(name) => name.encode(writer),
            KeyLocator::KeyDigest(items) => {
                (TLV_TYPE_SIGNATURE_KEY_DIGEST as u64).encode(writer)?;
                (items.len() as u64).encode(writer)?;
                writer.write(items)
            }
        }
    }
}

const TLV_TYPE_INTEREST: u32 = 5;
const TLV_TYPE_DATA: u32 = 6;

const TLV_TYPE_META_INFO: u32 = 20;
const TLV_TYPE_CONTENT: u32 = 21;
const TLV_TYPE_SIGNATURE_INFO: u32 = 22;
const TLV_TYPE_SIGNATURE_VALUE: u32 = 23;

const TLV_TYPE_CAN_BE_PREFIX: u32 = 33;
const TLV_TYPE_MUST_BE_FRESH: u32 = 18;
const TLV_TYPE_FORWARDING_HINT: u32 = 30;
const TLV_TYPE_NONCE: u32 = 10;
const TLV_TYPE_INTEREST_LIFETIME: u32 = 12;
const TLV_TYPE_HOP_LIMIT: u32 = 34;
const TLV_TYPE_APPLICATION_PARAMETERS: u32 = 36;
const TLV_TYPE_INTEREST_SIGNATURE_INFO: u32 = 44;
const TLV_TYPE_INTEREST_SIGNATURE_VALUE: u32 = 46;

const TLV_TYPE_META_INFO_CONTENT_TYPE: u32 = 24;
const TLV_TYPE_META_INFO_FRESHNESS_PERIOD: u32 = 25;
const TLV_TYPE_META_INFO_FINAL_BLOCK_ID: u32 = 26;

const TLV_TYPE_SIGNATURE_TYPE: u32 = 27;
const TLV_TYPE_SIGNATURE_KEY_DIGEST: u32 = 28;
const TLV_TYPE_SIGNATURE_KEY_LOCATOR: u32 = 29;
const TLV_TYPE_SIGNATURE_NONCE: u32 = 38;
const TLV_TYPE_SIGNATURE_TIME: u32 = 40;
const TLV_TYPE_SIGNATURE_SEQ_NUM: u32 = 42;

#[cfg(test)]
mod tests {

    #[test]
    fn test_key_locator() {}

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
    }
}
