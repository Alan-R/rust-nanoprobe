use std::mem::size_of;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("TLV error: {0}")]
pub struct TLVError(pub(crate) String);

impl From<&str> for TLVError {
    fn from(arg: &str) -> Self {
        Self(arg.to_string())
    }
}

impl From<String> for TLVError {
    fn from(arg: String) -> Self {
        Self(arg)
    }
}
type TLVResult<T> = Result<T, TLVError>;

type TlvType = u16; // Type of the TLV 'type' field
type TlvLen = u32; // Type of the TLV 'length' field

// Effectively, all our TLV objects start with a Type and a Length field, conceptually looking like this...
// But because everything is in network byte order, this struct isn't useful in the Rust code.
// struct TLVPrefix {
//    itype: TlvType, // But in "network byte order"
//    ilen: TlvLen, // But in "network byte order"
// }

// Offset to the beginning of the Value
const VALUE_OFFSET: usize = size_of::<TlvType>() + size_of::<TlvLen>();
const LEN_OFFSET: usize = size_of::<TlvType>();

fn get_tlv_len(stream: &[u8]) -> usize {
    (((stream[3 + LEN_OFFSET] as u32) << 24)
        + ((stream[2 + LEN_OFFSET] as u32) << 16)
        + ((stream[1 + LEN_OFFSET] as u32) << 8)
        + stream[0 + LEN_OFFSET] as u32) as usize
}
fn deserialize_u8(stream: &[u8]) -> TLVResult<u8> {
    if stream.len() < VALUE_OFFSET + size_of::<u8>() {
        Err(TLVError(
            format!("stream {} too_short for u8", stream.len()).to_string(),
        ))
    } else if get_tlv_len(&stream) != size_of::<u8>() {
        Err(TLVError(
            format!("incorrect u8 length: {}", get_tlv_len(stream)).to_string(),
        ))
    } else {
        Ok(stream[0 + VALUE_OFFSET])
    }
}

fn deserialize_u16(stream: &[u8]) -> TLVResult<u16> {
    if stream.len() < VALUE_OFFSET + size_of::<u16>() {
        Err(TLVError(
            format!("stream {} too_short for u16", stream.len()).to_string(),
        ))
    } else if get_tlv_len(stream) != size_of::<u16>() {
        Err(TLVError(
            format!("incorrect u16 length: {}", get_tlv_len(stream)).to_string(),
        ))
    } else {
        Ok(((stream[1 + VALUE_OFFSET] as u16) << 8) + stream[0 + VALUE_OFFSET] as u16)
    }
}

fn deserialize_u24(stream: &[u8]) -> TLVResult<u32> {
    if stream.len() < VALUE_OFFSET + 3 {
        Err(TLVError(
            format!("stream {} too_short for u24", stream.len()).to_string(),
        ))
    } else if get_tlv_len(stream) != 3 {
        Err(TLVError(
            format!("incorrect u24 length: {}", get_tlv_len(stream)).to_string(),
        ))
    } else {
        Ok(((stream[2 + VALUE_OFFSET] as u32) << 16)
            + ((stream[1 + VALUE_OFFSET] as u32) << 8)
            + stream[0 + VALUE_OFFSET] as u32)
    }
}

fn deserialize_u32(stream: &[u8]) -> TLVResult<u32> {
    if stream.len() < VALUE_OFFSET + size_of::<u32>() {
        Err(TLVError(
            format!("stream {} too_short for u32", stream.len()).to_string(),
        ))
    } else if get_tlv_len(stream) != size_of::<u32>() {
        Err(TLVError(
            format!("incorrect u32 length: {}", get_tlv_len(stream)).to_string(),
        ))
    } else {
        Ok(((stream[3 + VALUE_OFFSET] as u32) << 24)
            + ((stream[2 + VALUE_OFFSET] as u32) << 16)
            + ((stream[1 + VALUE_OFFSET] as u32) << 8)
            + stream[0 + VALUE_OFFSET] as u32)
    }
}

fn deserialize_u64(stream: &[u8]) -> TLVResult<u64> {
    if stream.len() < VALUE_OFFSET + size_of::<u64>() {
        Err(TLVError(
            format!("incorrect u64 length: {}", get_tlv_len(stream)).to_string(),
        ))
    } else if get_tlv_len(stream) != size_of::<u64>() {
        Err(TLVError(
            format!("incorrect u64 length: {}", get_tlv_len(stream)).to_string(),
        ))
    } else {
        Ok(((stream[7 + VALUE_OFFSET] as u64) << 56)
            + ((stream[6 + VALUE_OFFSET] as u64) << 48)
            + ((stream[5 + VALUE_OFFSET] as u64) << 40)
            + ((stream[4 + VALUE_OFFSET] as u64) << 32)
            + ((stream[3 + VALUE_OFFSET] as u64) << 24)
            + ((stream[2 + VALUE_OFFSET] as u64) << 16)
            + ((stream[1 + VALUE_OFFSET] as u64) << 8)
            + (stream[0 + VALUE_OFFSET] as u64))
    }
}

fn serialize_u16_raw(stream: &mut Vec<u8>, data: u16) {
    for item in [(data & 0xff) as u8, (data >> 8) as u8] {
        stream.push(item);
    }
}
fn serialize_u32_raw(stream: &mut Vec<u8>, data: u32) {
    for item in [
        (data & 0xff) as u8,
        ((data >> 8) & 0xff) as u8,
        ((data >> 16) & 0xff) as u8,
        ((data >> 24) & 0xff) as u8,
    ] {
        stream.push(item);
    }
}
fn serialize_u24_raw(stream: &mut Vec<u8>, data: u32) {
    for item in [
        (data & 0xff) as u8,
        ((data >> 8) & 0xff) as u8,
        ((data >> 16) & 0xff) as u8,
    ] {
        stream.push(item);
    }
}
fn serialize_u64_raw(stream: &mut Vec<u8>, data: u64) {
    for item in [
        (data & 0xff) as u8,
        ((data >> 8) & 0xff) as u8,
        ((data >> 16) & 0xff) as u8,
        ((data >> 24) & 0xff) as u8,
        ((data >> 32) & 0xff) as u8,
        ((data >> 40) & 0xff) as u8,
        ((data >> 48) & 0xff) as u8,
        ((data >> 56) & 0xff) as u8,
    ] {
        stream.push(item);
    }
}

fn serialize_u8(stream: &mut Vec<u8>, itype: u16, item: u8) {
    serialize_u16_raw(stream, itype);
    serialize_u32_raw(stream, 1u32);
    stream.push(item);
}

fn serialize_u16(stream: &mut Vec<u8>, itype: u16, item: u16) {
    serialize_u16_raw(stream, itype);
    serialize_u32_raw(stream, 2u32);
    serialize_u16_raw(stream, item);
}

fn serialize_u24(stream: &mut Vec<u8>, itype: u16, item: u32) {
    serialize_u16_raw(stream, itype);
    serialize_u32_raw(stream, 3u32);
    serialize_u24_raw(stream, item);
}

fn serialize_u32(stream: &mut Vec<u8>, itype: u16, item: u32) {
    serialize_u16_raw(stream, itype);
    serialize_u32_raw(stream, 4u32);
    serialize_u32_raw(stream, item);
}

fn serialize_u64(stream: &mut Vec<u8>, itype: u16, item: u64) {
    serialize_u16_raw(stream, itype);
    serialize_u32_raw(stream, 8u32);
    serialize_u64_raw(stream, item);
}
#[cfg(test)]
// Should these be UNIX-only tests and have a different mod for non-UNIX specific tests?
mod tests {
    use super::*;

    #[test]
    fn test_u8() {
        let stream = &mut Vec::new();
        let test_data = 255u8; // Not the same as the type or length
        serialize_u8(stream, 1, test_data);
        let result = deserialize_u8(&stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }

    #[test]
    fn test_u16() {
        let stream = &mut Vec::new();
        let test_data = 0xeffe; // Every byte is different
        serialize_u16(stream, 1, test_data);
        let result = deserialize_u16(&stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }
    #[test]
    fn test_u24() {
        let stream = &mut Vec::new();
        let test_data = 0xedbeefu32; // Every byte is different
        serialize_u24(stream, 1, test_data);
        let result = deserialize_u24(&stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }
    #[test]
    fn test_u32() {
        let stream = &mut Vec::new();
        let test_data = 0xfeedbeefu32; // Every byte is different
        serialize_u32(stream, 1, test_data);
        let result = deserialize_u32(&stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }
    #[test]
    fn test_u64() {
        let stream = &mut Vec::new();
        let test_data = 0xfeedbeefb1e55ed1; // Every byte is different
        serialize_u64(stream, 1, test_data);
        let result = deserialize_u64(&stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }
}
