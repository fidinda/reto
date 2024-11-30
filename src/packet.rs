use core::num::{NonZeroU16, NonZeroU32};
use crate::{encode::{Encodable, EncodingError}, parse_tlvs, tlv::DecodingError, Name, NameComponent, TLVEntry, TLV};


pub struct Interest<'a> {
    pub name: Name<'a>,
    pub can_be_prefix: bool,
    pub must_be_fresh: bool,
    pub forwarding_hint: Option<&'a [u8]>,
    pub nonce: Option<[u8;4]>,
    pub interest_lifetime : Option<u64>,
    pub hop_limit: Option<u8>,
    pub application_parameters: Option<ApplicationParameters<'a>>,

    // The specification allows for any number of TLVs that are not currently known,
    //  but that should still be preserved. 
    // If any unknown TLV has a critical type, we must stop procesing the packet.
    // To avoid allocations we keep an array of pointers to _possible_ places
    //  where zero or more unknown TLVs might happen. We store them as slices.
    // They cannot occur before name or after the signature.
    pub unknown_tlvs: [&'a [u8]; 8],

    // In signed interests we need to hash a non-contiguous part of the packet
    //  as we need to skip the last part of the name 
    //  (which contains the hash of the portion that includes the signature).

    pub signed_ranges_in_parent_tlv: Option<[(usize, usize);2]>,
}

impl<'a> Interest<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        todo!();
        None
    }
}

impl<'a> Encodable for Interest<'a> {
    fn encoded_length(&self) -> usize {
        todo!()
    }

    fn encode<B : crate::encode::Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        todo!()
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

    // This captures the range of everything from the beginnig of name and up to
    //  the end of signature_info. It does not cover the top-level "Data packet" TLV.
    // We do not keep the reference to the buffer as it only applies to the original.
    pub signed_range_in_parent_tlv: (usize, usize),
}

impl<'a> Data<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        let mut inner_tlvs = parse_tlvs(bytes);

        // The first must be the name
        let name_tlv = inner_tlvs.next()?.ok()?.tlv;
        if name_tlv.typ.get() != TLV_TYPE_NAME {
            return None // Name must be the first TLV
        }
        let name = Name::from_bytes(name_tlv.val)?;
        
        // The rest should typcially be a few known TLV in order,
        //  but they may contain unspecificed tlvs too, which we store.
        let mut meta_info = None;
        let mut content = None;
        let mut signature_info = None;
        let mut signature_info_last_byte_index = 0;
        let mut signature_value = None;
        let mut unknown_tlv_ranges = [(0usize,0usize); 3];
        
        let known = [
            TLV_TYPE_META_INFO, TLV_TYPE_CONTENT, TLV_TYPE_SIGNATURE_INFO, TLV_TYPE_SIGNATURE_VALUE
        ];
        let mut latest_seen = 0;

        while let Some(entry) = inner_tlvs.next() {
            let entry = entry.ok()?;
            let byte_range = entry.byte_range;
            match maybe_parse(entry, &known, unknown_tlv_ranges[latest_seen]) {
                MaybeParseResult::Known(idx, tlv) => {
                    latest_seen = idx;
                    match idx {
                        0 => meta_info = Some(MetaInfo::from_bytes(tlv.val)?),
                        1 => content = Some(tlv.val),
                        2 => signature_info = {
                            signature_info_last_byte_index = byte_range.1;
                            Some(SignatureInfo::from_bytes(tlv.val)?)
                        },
                        3 => signature_value = Some(tlv.val),
                        _ => unreachable!()
                    }
                },
                MaybeParseResult::Unknown(range, tlv) => {
                    if tlv.is_critical() {
                        return None // There is a critical unknown type, so we must bail
                    }
                    unknown_tlv_ranges[latest_seen] = range
                },
            }
        } 

        let signature_info = signature_info?;
        let signature_value = signature_value?;
        let unknown_tlvs = unknown_tlv_ranges.map(|(b, e)| &bytes[b..e]);
        let signed_range_in_parent_tlv = (0usize, signature_info_last_byte_index);

        Some( Data { 
            name, 
            meta_info, 
            content, 
            signature_info, 
            signature_value, 
            unknown_tlvs, 
            signed_range_in_parent_tlv 
        })
    }
}

impl<'a> Encodable for Data<'a> {
    fn encoded_length(&self) -> usize {
        let mut len = self.unknown_tlvs.iter().fold(0, |a,b| a + b.len());
        len += self.name.encoded_length();
        if let Some(meta_info) = &self.meta_info {
            len += meta_info.encoded_length();
        }
        
        todo!()
    }

    fn encode<B : crate::encode::Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        todo!()
    }
}


enum MaybeParseResult<'a> {
    Known(usize, TLV<'a>),
    Unknown((usize, usize), TLV<'a>)
}

fn maybe_parse<'a>(entry: TLVEntry<'a>, known: &[u32], current_unknown_range: (usize, usize)) -> MaybeParseResult<'a> {
    if let Some(p) = known.iter().position(|x| &entry.tlv.typ.get() == x) {
        MaybeParseResult::Known(p, entry.tlv)
    } else {
        let range = if current_unknown_range == (0,0) {
            entry.byte_range
        } else {
            debug_assert!(current_unknown_range.1 == entry.byte_range.0);
            (current_unknown_range.0, entry.byte_range.1)
        };
        MaybeParseResult::Unknown(range, entry.tlv)
    }
}

pub struct ApplicationParameters<'a> {
    payload: &'a [u8],
    signature: Option<(InterestSignatureInfo<'a>, &'a [u8])>,
}

impl<'a> ApplicationParameters<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        None
    }
}



pub struct MetaInfo<'a> {
    pub content_type: Option<ContentType>,
    pub freshness_period: Option<u64>,
    pub final_block_id: Option<NameComponent<'a>>,
    pub unknown_tlvs: [&'a [u8]; 4],
}

impl<'a> MetaInfo<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        // TODO: we are ignoring the unknowns here, but maybe they are necessary too?
        // "ndn-cxx allows arbitrary application-defined TLVs to appear at the end of MetaInfo."

        let mut unknown_tlvs = [[].as_slice(); 4];

        let mut content_type = None;
        let mut freshness_period = None;
        let mut final_block_id = None;

        let mut inner_tlvs = parse_tlvs(bytes);

        while let Some(inner_tlv) = inner_tlvs.next() {
            let inner_tlv = inner_tlv.ok()?.tlv;
            match inner_tlv.typ.get() {
                TLV_TYPE_META_INFO_CONTENT_TYPE => content_type = Some(inner_tlv.value_as_unsigned()?.into()),
                TLV_TYPE_META_INFO_FRESHNESS_PERIOD => freshness_period = Some(inner_tlv.value_as_unsigned()?),
                TLV_TYPE_META_INFO_FINAL_BLOCK_ID => if let Some(Ok(nc_tlv)) = parse_tlvs(inner_tlv.val).next() {
                    let typ: NonZeroU16 = nc_tlv.tlv.typ.try_into().unwrap();
                    final_block_id = Some(NameComponent { typ, bytes: nc_tlv.tlv.val })
                },
                _ => {}
            }
        }

        Some(MetaInfo { content_type, freshness_period, final_block_id, unknown_tlvs })
    }
}


impl<'a> Encodable for MetaInfo<'a> {
    fn encoded_length(&self) -> usize {
        let mut len = self.unknown_tlvs.iter().fold(0, |a,b| a + b.len());
        if let Some(ct) = self.content_type {
            let ct : u64 = ct.into();
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
            let tlv : TLV<'_> = final_block_id.into();
            len += tlv.encoded_length()
        }

        len
    }

    fn encode<B : crate::encode::Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        let encoded_len = self.encoded_length();
        (TLV_TYPE_META_INFO as u64).encode(buffer)?;
        (encoded_len as u64).encode(buffer)?;
        buffer.push(self.unknown_tlvs[0])?;
        if let Some(ct) = self.content_type {
            (TLV_TYPE_META_INFO_CONTENT_TYPE as u64).encode(buffer)?;
            let ct : u64 = ct.into();
            (ct.encoded_length() as u64).encode(buffer)?;
            ct.encode(buffer)?;
        }
        buffer.push(self.unknown_tlvs[1])?;
        if let Some(freshness_period) = self.freshness_period {
            (TLV_TYPE_META_INFO_FRESHNESS_PERIOD as u64).encode(buffer)?;
            (freshness_period.encoded_length() as u64).encode(buffer)?;
            freshness_period.encode(buffer)?;
        }
        buffer.push(self.unknown_tlvs[2])?;
        if let Some(final_block_id) = self.final_block_id {
            let tlv : TLV<'_> = final_block_id.into();
            tlv.encode(buffer)?;
        }
        buffer.push(self.unknown_tlvs[3])
    }
}



#[derive(Clone, Copy)]
pub enum ContentType {
    Blob,
    Key,
    Link,
    Nack,
    Other(u64),
}

impl From<u64> for ContentType {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::Blob,
            1 => Self::Key,
            2 => Self::Link,
            3 => Self::Nack,
            u => Self::Other(u)
        }
    }
}

impl From<ContentType> for u64 {
    fn from(value: ContentType) -> Self {
        match value {
            ContentType::Blob => 0,
            ContentType::Key => 1,
            ContentType::Link => 2,
            ContentType::Nack => 3,
            ContentType::Other(u) => u
        }
    }
}


pub struct SignatureInfo<'a> {
    pub signature_type: SignatureType,
    pub key_locator: Option<KeyLocator<'a>>,
}

impl<'a> SignatureInfo<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        let mut inner_tlvs = parse_tlvs(bytes);
        let signature_type_tlv =  inner_tlvs.next()?.ok()?.tlv;
        if signature_type_tlv.typ.get() != TLV_TYPE_SIGNATURE_TYPE {
            return None
        }
        let signature_type = signature_type_tlv.value_as_unsigned()?.into();
        
        let mut key_locator = None;

        if let Some(key_locator_entry) = inner_tlvs.next() {
            let key_locator_tlv = key_locator_entry.ok()?.tlv;
            if key_locator_tlv.typ.get() == TLV_TYPE_SIGNATURE_KEY_LOCATOR {
                key_locator = Some(KeyLocator::from_bytes(key_locator_tlv.val)?)
            }
        }

        Some(Self { signature_type, key_locator })
    }
}

impl<'a> Encodable for SignatureInfo<'a> {
    fn encoded_length(&self) -> usize {
        todo!()
    }

    fn encode<B : crate::encode::Buffer>(&self, buffer: &mut B) -> Result<(), EncodingError> {
        todo!()
    }
}


pub struct InterestSignatureInfo<'a> {
    pub signature_type: SignatureType,
    pub key_locator: Option<KeyLocator<'a>>,
    pub nonce: Option<&'a [u8]>,
    pub signature_time: Option<u64>,
    pub signature_seq_num: Option<u64>,
}

impl<'a> InterestSignatureInfo<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        let mut inner_tlvs = parse_tlvs(bytes);
        let signature_type_tlv =  inner_tlvs.next()?.ok()?.tlv;
        if signature_type_tlv.typ.get() != TLV_TYPE_SIGNATURE_TYPE {
            return None
        }
        let signature_type = signature_type_tlv.value_as_unsigned()?.into();
        
        let mut key_locator = None;
        let mut nonce = None;
        let mut signature_time = None;
        let mut signature_seq_num = None;

        while let Some(entry) = inner_tlvs.next() {
            let tlv = entry.ok()?.tlv;
            match tlv.typ.get() {
                TLV_TYPE_SIGNATURE_KEY_LOCATOR => key_locator = Some(KeyLocator::from_bytes(tlv.val)?),
                TLV_TYPE_SIGNATURE_NONCE => nonce = Some(tlv.val),
                TLV_TYPE_SIGNATURE_TIME => signature_time = Some(tlv.value_as_unsigned()?),
                TLV_TYPE_SIGNATURE_SEQ_NUM => signature_seq_num = Some(tlv.value_as_unsigned()?),
                _ => {}
            }
        }

        Some(Self { signature_type, key_locator, nonce, signature_time, signature_seq_num })
    }
}

pub enum SignatureType {
    DigestSha256,
    SignatureSha256WithRsa,
    SignatureSha256WithEcdsa,
    SignatureHmacWithSha256,
    SignatureEd25519,
    Other(u64),
}


impl From<u64> for SignatureType {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::DigestSha256,
            1 => Self::SignatureSha256WithRsa,
            3 => Self::SignatureSha256WithEcdsa,
            4 => Self::SignatureHmacWithSha256,
            5 => Self::SignatureEd25519,
            u => Self::Other(u)
        }
    }
}

impl From<SignatureType> for u64 {
    fn from(value: SignatureType) -> Self {
        match value {
            SignatureType::DigestSha256 => 0,
            SignatureType::SignatureSha256WithRsa => 1,
            SignatureType::SignatureSha256WithEcdsa => 3,
            SignatureType::SignatureHmacWithSha256 => 4,
            SignatureType::SignatureEd25519 => 5,
            SignatureType::Other(u) => u
        }
    }
}


pub enum KeyLocator<'a> {
    Name(Name<'a>),
    KeyDigest(&'a [u8]),
}


impl<'a> KeyLocator<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        let inner_tlv = parse_tlvs(bytes).next()?.ok()?.tlv;
        match inner_tlv.typ.get() {
            TLV_TYPE_NAME => Some(Self::Name(Name::from_bytes(inner_tlv.val)?)),
            TLV_TYPE_SIGNATURE_KEY_DIGEST => Some(Self::KeyDigest(&inner_tlv.val)),
            _ => None,
        }
    }
}



pub enum PacketParseResult<'a> {
    Interest(Interest<'a>),
    Data(Data<'a>),
    UnknownType(NonZeroU32),
    TLVDecodingError(DecodingError),
    PacketDecodingError,
}

const TLV_TYPE_INTEREST: u32 = 5;
const TLV_TYPE_DATA: u32 = 6;

const TLV_TYPE_NAME: u32 = 7;

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


/*
const TLV_TYPE_INTEREST: NonZeroU32 = unsafe {
    NonZeroU32::new_unchecked(5)
};


const TLV_TYPE_DATA: NonZeroU32 = NonZeroU32::new(6).unwrap();

const TLV_TYPE_NAME: NonZeroU32 = NonZeroU32::new(7).unwrap();

const TLV_TYPE_META_INFO: NonZeroU32 = NonZeroU32::new(20).unwrap();
const TLV_TYPE_CONTENT: NonZeroU32 = NonZeroU32::new(21).unwrap();
const TLV_TYPE_SIGNATURE_INFO: NonZeroU32 = NonZeroU32::new(22).unwrap();
const TLV_TYPE_SIGNATURE_VALUE: NonZeroU32 = NonZeroU32::new(23).unwrap();

const TLV_TYPE_CAN_BE_PREFIX: NonZeroU32 = NonZeroU32::new(33).unwrap();
const TLV_TYPE_MUST_BE_FRESH: NonZeroU32 = NonZeroU32::new(18).unwrap();
const TLV_TYPE_FORWARDING_HINT: NonZeroU32 = NonZeroU32::new(30).unwrap();
const TLV_TYPE_NONCE: NonZeroU32 = NonZeroU32::new(10).unwrap();
const TLV_TYPE_INTEREST_LIFETIME: NonZeroU32 = NonZeroU32::new(12).unwrap();
const TLV_TYPE_HOP_LIMIT: NonZeroU32 = NonZeroU32::new(34).unwrap();
const TLV_TYPE_APPLICATION_PARAMETERS: NonZeroU32 = NonZeroU32::new(36).unwrap();
const TLV_TYPE_INTEREST_SIGNATURE_INFO: NonZeroU32 = NonZeroU32::new(44).unwrap();
const TLV_TYPE_INTEREST_SIGNATURE_VALUE: NonZeroU32 = NonZeroU32::new(46).unwrap();

const TLV_TYPE_META_INFO_CONTENT_TYPE: NonZeroU32 = NonZeroU32::new(24).unwrap();
const TLV_TYPE_META_INFO_FRESHNESS_PERIOD: NonZeroU32 = NonZeroU32::new(25).unwrap();
const TLV_TYPE_META_INFO_FINAL_BLOCK_ID: NonZeroU32 = NonZeroU32::new(26).unwrap();

const TLV_TYPE_SIGNATURE_TYPE: NonZeroU32 = NonZeroU32::new(27).unwrap();
const TLV_TYPE_SIGNATURE_KEY_DIGEST: NonZeroU32 = NonZeroU32::new(28).unwrap();
const TLV_TYPE_SIGNATURE_KEY_LOCATOR: NonZeroU32 = NonZeroU32::new(29).unwrap();
const TLV_TYPE_SIGNATURE_NONCE: NonZeroU32 = NonZeroU32::new(38).unwrap();
const TLV_TYPE_SIGNATURE_TIME: NonZeroU32 = NonZeroU32::new(40).unwrap();
const TLV_TYPE_SIGNATURE_SEQ_NUM: NonZeroU32 = NonZeroU32::new(42).unwrap();
*/

pub fn parse_packet(bytes: &[u8]) -> Option<PacketParseResult<'_>> {
    parse_packets(bytes).next()
}

pub fn parse_packets(bytes: &[u8]) -> impl Iterator<Item = PacketParseResult<'_>> {
    parse_tlvs(bytes).map(|entry| {
        let entry: TLVEntry = match entry {
            Ok(entry) => entry,
            Err(e) => return PacketParseResult::TLVDecodingError(e),
        };

        match entry.tlv.typ.get() {
            TLV_TYPE_INTEREST => match Interest::from_bytes(entry.tlv.val) {
                Some(interest) => PacketParseResult::Interest(interest),
                None => PacketParseResult::PacketDecodingError,
            },
            TLV_TYPE_DATA => match Data::from_bytes(entry.tlv.val) {
                Some(data) => PacketParseResult::Data(data),
                None => PacketParseResult::PacketDecodingError,
            },
            _ => PacketParseResult::UnknownType(entry.tlv.typ)
        }
    })
}
