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
type TLVResult<T> = std::result::Result<T, TLVError>;

const TLV_OFFSET: usize = 6;

fn get_tlv_len(stream: &Vec<u8>) -> u32 {
    ((stream[3 + 2] as u32) << 24)
        + ((stream[2 + 2] as u32) << 16)
        + ((stream[1 + 2] as u32) << 8)
        + stream[0 + 2] as u32
}
fn deserialize_u8(stream: &Vec<u8>) -> TLVResult<u8> {
    if get_tlv_len(stream) != 1 {
        Err(TLVError("incorrect u8 length".to_string()))
    } else {
        Ok(stream[0 + TLV_OFFSET])
    }
}

fn deserialize_u16(stream: &Vec<u8>) -> TLVResult<u16> {
    if get_tlv_len(stream) != 2 {
        Err(TLVError("incorrect u16 length".to_string()))
    } else {
        Ok(((stream[1 + TLV_OFFSET] as u16) << 8) + stream[0 + TLV_OFFSET] as u16)
    }
}

fn deserialize_u24(stream: &Vec<u8>) -> TLVResult<u32> {
    if get_tlv_len(stream) != 3 {
        Err(TLVError("incorrect u24 length".to_string()))
    } else {
        Ok(((stream[2 + TLV_OFFSET] as u32) << 16)
            + ((stream[1 + TLV_OFFSET] as u32) << 16)
            + stream[0 + TLV_OFFSET] as u32)
    }
}

fn deserialize_u32(stream: &Vec<u8>) -> TLVResult<u32> {
    if get_tlv_len(stream) != 4 {
        Err(TLVError("incorrect u32 length".to_string()))
    } else {
        Ok(((stream[3 + TLV_OFFSET] as u32) << 24)
            + ((stream[2 + TLV_OFFSET] as u32) << 16)
            + ((stream[1 + TLV_OFFSET] as u32) << 8)
            + stream[0 + TLV_OFFSET] as u32)
    }
}

fn deserialize_u64(stream: &Vec<u8>) -> TLVResult<u64> {
    if get_tlv_len(stream) != 8 {
        Err(TLVError("incorrect u64 length".to_string()))
    } else {
        Ok(((stream[7 + TLV_OFFSET] as u64) << 56)
            + ((stream[6 + TLV_OFFSET] as u64) << 48)
            + ((stream[5 + TLV_OFFSET] as u64) << 40)
            + ((stream[4 + TLV_OFFSET] as u64) << 32)
            + ((stream[3 + TLV_OFFSET] as u64) << 24)
            + ((stream[2 + TLV_OFFSET] as u64) << 16)
            + ((stream[1 + TLV_OFFSET] as u64) << 8)
            + (stream[0 + TLV_OFFSET] as u64))
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
        let test_data = 255u8;
        serialize_u8(stream, 1, test_data);
        println!("STREAM: {:?}", stream);
        let result = deserialize_u8(stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }

    #[test]
    fn test_u16() {
        let stream = &mut Vec::new();
        let test_data = 0xffffu16;
        serialize_u16(stream, 1, test_data);
        let result = deserialize_u16(stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }
    #[test]
    fn test_u32() {
        let stream = &mut Vec::new();
        let test_data = 0xfeedbeefu32;
        serialize_u32(stream, 1, test_data);
        let result = deserialize_u32(stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }
    #[test]
    fn test_u64() {
        let stream = &mut Vec::new();
        let test_data = 0xfeedbeefdeadbea7u64;
        serialize_u64(stream, 1, test_data);
        let result = deserialize_u64(stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }
}
