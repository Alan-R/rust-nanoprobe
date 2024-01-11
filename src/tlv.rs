// use serde_json::Value;
use crate::addresses::AddressFamily;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::string::String;
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
#[derive(Debug, PartialEq)]
/// TLVDeserializerOk is the success return value from deserializing actions
pub struct TLVDeserializeOk<T> {
    bytes: usize, // How many bytes were read?
    result: T,    // What was the result of the deserialization?
}
/// TLVResult is the Result of all deserialization actions
pub type TLVResult<T> = Result<TLVDeserializeOk<T>, TLVError>;

type TlvType = u16; // Type of the TLV 'type' field
type TlvLen = u32; // Type of the TLV 'length' field

/// Effectively, all our TLV objects start with a Type and a Length field, conceptually looking like this...
/// But because everything is in network byte order, this struct isn't useful in the Rust code.
/// struct TLVPrefix {
///    itype: TlvType, // But in "network byte order"
///    ilen: TlvLen, // But in "network byte order"
/// }
/// We don't put any padding between items on the wire, since in most cases we have to
/// convert from network byte order to local byte order. This also means we don't care about local compiler
/// and hardware conventions about padding and alignment.

// Offset to the beginning of the Value
const VALUE_OFFSET: usize = size_of::<TlvType>() + size_of::<TlvLen>();
// Offset to the beginning of the Length field
const LEN_OFFSET: usize = size_of::<TlvType>();

#[derive(Debug, PartialEq)]
/// Sequence numbers include session id to make replay attacks difficult.
/// Session IDs are incremented each time an endpoint restarts.
pub struct SequenceNumber {
    reqid: u64,     // The sequence number for this session and queue.
    sessionid: u32, // The session id for this queue. Incremented each time the protocol restarts.
    qid: u16, // Allows for more than one communication stream between endpoints. Not sure it's needed...
}
// There is no extra padding on the wire after the end of the data in a SequenceNumber object.
const SEQNO_LEN: usize = size_of::<u64>() + size_of::<u32>() + size_of::<u16>(); // No padding at the end!
/// Digital signature frame
#[derive(Debug, PartialEq)]
pub struct Signature<'a> {
    sign_provider: u8,
    sign_type: u8,
    signature: Box<&'a [u8]>,
}
const SIGNATURE_FRAME_TYPE: u16 = 1;
const MIN_SIGNATURE_LEN: usize = 3 * size_of::<u8>();
impl Signature<'_> {
    fn is_valid(&self) -> TLVResult<()> {
        if self.sign_provider == 0 && self.sign_type == 0 {
            Ok(TLVDeserializeOk::<()> {
                bytes: 0,
                result: (),
            })
        } else {
            Err(TLVError(format!(
                "invalid signature type: {}:{}",
                self.sign_provider, self.sign_type
            )))
        }
    }
}
#[derive(Debug, PartialEq)]
pub struct Compression<'a> {
    uncompressed_size: u32,
    compression_type: u8,
    data: Box<&'a [u8]>,
}
impl Compression<'_> {
    fn is_valid(&self) -> TLVResult<()> {
        Ok(TLVDeserializeOk::<()> {
            bytes: 0,
            result: (),
        })
    }
}
#[derive(Debug, PartialEq)]
pub struct Encryption<'a> {
    sender_key_id: String,
    receiver_key_id: String,
    data: Box<&'a [u8]>,
}
impl Encryption<'_> {
    fn is_valid(&self) -> TLVResult<()> {
        Ok(TLVDeserializeOk::<()> {
            bytes: 0,
            result: (),
        })
    }
}

//=====================================================================
//
//  De-serialization code starts below
//  We take data out of a packet, and transform it back to in-memory data
//
//=====================================================================

#[inline]
fn get_tlv_len(stream: &[u8]) -> usize {
    deserialize_u32_raw(&stream[LEN_OFFSET..LEN_OFFSET + 4]) as usize
}
fn deserialize_u8(stream: &[u8]) -> TLVResult<u8> {
    if stream.len() < VALUE_OFFSET + size_of::<u8>() {
        Err(TLVError(format!(
            "stream {} too_short for u8",
            stream.len()
        )))
    } else if get_tlv_len(&stream) != size_of::<u8>() {
        Err(TLVError(format!(
            "incorrect u8 length: {}",
            get_tlv_len(stream)
        )))
    } else {
        Ok(TLVDeserializeOk::<u8> {
            bytes: VALUE_OFFSET + size_of::<u8>(),
            result: stream[0 + VALUE_OFFSET],
        })
    }
}

#[inline]
fn deserialize_u16_raw(stream: &[u8]) -> u16 {
    ((stream[1] as u16) << 8) + stream[0] as u16
}
#[inline]
fn deserialize_u32_raw(stream: &[u8]) -> u32 {
    ((stream[3] as u32) << 24)
        + ((stream[2] as u32) << 16)
        + ((stream[1] as u32) << 8)
        + stream[0] as u32
}

#[inline]
fn deserialize_u64_raw(stream: &[u8]) -> u64 {
    ((stream[7] as u64) << 56)
        + ((stream[6] as u64) << 48)
        + ((stream[5] as u64) << 40)
        + ((stream[4] as u64) << 32)
        + ((stream[3] as u64) << 24)
        + ((stream[2] as u64) << 16)
        + ((stream[1] as u64) << 8)
        + (stream[0] as u64)
}

fn deserialize_u16(stream: &[u8]) -> TLVResult<u16> {
    if stream.len() < VALUE_OFFSET + size_of::<u16>() {
        Err(TLVError(format!(
            "stream {} too_short for u16",
            stream.len()
        )))
    } else if get_tlv_len(stream) != size_of::<u16>() {
        Err(TLVError(format!(
            "incorrect u16 length: {}",
            get_tlv_len(stream)
        )))
    } else {
        Ok(TLVDeserializeOk::<u16> {
            bytes: VALUE_OFFSET + size_of::<u16>(),
            result: deserialize_u16_raw(&stream[VALUE_OFFSET..VALUE_OFFSET + 2]),
        })
    }
}

fn deserialize_u24(stream: &[u8]) -> TLVResult<u32> {
    if stream.len() < VALUE_OFFSET + 3 {
        Err(TLVError(format!(
            "stream {} too_short for u24",
            stream.len()
        )))
    } else if get_tlv_len(stream) != 3 {
        Err(TLVError(format!(
            "incorrect u24 length: {}",
            get_tlv_len(stream)
        )))
    } else {
        Ok(TLVDeserializeOk::<u32> {
            bytes: VALUE_OFFSET + 3,
            result: ((stream[2 + VALUE_OFFSET] as u32) << 16)
                + ((stream[1 + VALUE_OFFSET] as u32) << 8)
                + stream[0 + VALUE_OFFSET] as u32,
        })
    }
}

fn deserialize_u32(stream: &[u8]) -> TLVResult<u32> {
    if stream.len() < VALUE_OFFSET + size_of::<u32>() {
        Err(TLVError(format!(
            "stream {} too_short for u32",
            stream.len()
        )))
    } else if get_tlv_len(stream) != size_of::<u32>() {
        Err(TLVError(format!(
            "incorrect u32 length: {}",
            get_tlv_len(stream)
        )))
    } else {
        Ok(TLVDeserializeOk::<u32> {
            bytes: VALUE_OFFSET + size_of::<u32>(),
            result: deserialize_u32_raw(&stream[VALUE_OFFSET..VALUE_OFFSET + 4]),
        })
    }
}

fn deserialize_u64(stream: &[u8]) -> TLVResult<u64> {
    if stream.len() < VALUE_OFFSET + size_of::<u64>() {
        Err(TLVError(format!(
            "stream too short for u64: {}",
            get_tlv_len(stream)
        )))
    } else if get_tlv_len(stream) != size_of::<u64>() {
        Err(TLVError(format!(
            "incorrect u64 length: {}",
            get_tlv_len(stream)
        )))
    } else {
        Ok(TLVDeserializeOk::<u64> {
            bytes: VALUE_OFFSET + size_of::<u64>(),
            result: deserialize_u64_raw(&stream[VALUE_OFFSET..VALUE_OFFSET + 8]),
        })
    }
}
fn deserialize_ipv4_raw(stream: &[u8]) -> Ipv4Addr {
    Ipv4Addr::from([stream[0], stream[1], stream[2], stream[3]])
}
fn deserialize_ipv6_raw(stream: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from([
        stream[0], stream[1], stream[2], stream[3], stream[4], stream[5], stream[6], stream[7],
        stream[8], stream[9], stream[10], stream[11], stream[12], stream[13], stream[14],
        stream[15],
    ])
}

fn deserialize_ipv4(stream: &[u8]) -> TLVResult<Ipv4Addr> {
    if stream.len() < VALUE_OFFSET + size_of::<Ipv4Addr>() + 4 {
        return Err(TLVError(format!(
            "stream too short for Ipv4Addr: {}",
            stream.len(),
        )));
    } else {
        let address_family = deserialize_u16_raw(&stream[VALUE_OFFSET + 2..VALUE_OFFSET + 4]);
        if address_family != AddressFamily::Ipv4 as u16 {
            return Err(TLVError(format!(
                "Not an IPv4 address: address family = {}",
                address_family
            )));
        }
    }
    if get_tlv_len(stream) != size_of::<Ipv4Addr>() + 4 {
        Err(TLVError(format!(
            "incorrect IPv4 length: {}",
            get_tlv_len(stream)
        )))
    } else {
        Ok(TLVDeserializeOk::<Ipv4Addr> {
            bytes: VALUE_OFFSET + size_of::<Ipv4Addr>() + 4,
            result: deserialize_ipv4_raw(&stream[VALUE_OFFSET + 4..VALUE_OFFSET + 8]),
        })
    }
}

fn deserialize_ipv6(stream: &[u8]) -> TLVResult<Ipv6Addr> {
    if stream.len() < VALUE_OFFSET + 16 + 4 {
        return Err(TLVError(format!(
            "stream too short for Ipv6Addr: {}",
            stream.len(),
        )));
    } else {
        let address_family = deserialize_u16_raw(&stream[VALUE_OFFSET + 2..VALUE_OFFSET + 4]);
        if address_family != AddressFamily::Ipv6 as u16 {
            return Err(TLVError(format!(
                "Not an IPv4 address: address family = {}",
                address_family
            )));
        }
    }

    if get_tlv_len(stream) != size_of::<Ipv6Addr>() + 4 {
        Err(TLVError(format!(
            "incorrect IPv6 length: {}",
            get_tlv_len(stream)
        )))
    } else {
        Ok(TLVDeserializeOk::<Ipv6Addr> {
            bytes: VALUE_OFFSET + size_of::<Ipv6Addr>() + 4,
            result: deserialize_ipv6_raw(&stream[VALUE_OFFSET + 4..VALUE_OFFSET + 20]),
        })
    }
}

fn deserialize_socketaddr(stream: &[u8]) -> TLVResult<SocketAddr> {
    if stream.len() < VALUE_OFFSET + size_of::<Ipv4Addr>() + 4 {
        return Err(TLVError(format!(
            "stream too short for SocketAddr: {}",
            stream.len()
        )));
    } else {
        let port = deserialize_u16_raw(&stream[VALUE_OFFSET..VALUE_OFFSET + 2]);
        let address_family = deserialize_u16_raw(&stream[VALUE_OFFSET + 2..VALUE_OFFSET + 4]);
        if address_family == AddressFamily::Ipv4 as u16 {
            match deserialize_ipv4(stream) {
                Err(oops) => Err(oops),
                Ok(v4) => Ok(TLVDeserializeOk::<SocketAddr> {
                    bytes: v4.bytes,
                    result: SocketAddr::V4(SocketAddrV4::new(v4.result, port)),
                }),
            }
        } else if address_family == AddressFamily::Ipv6 as u16 {
            match deserialize_ipv6(stream) {
                Err(oops) => Err(oops),
                Ok(v6) => Ok(TLVDeserializeOk::<SocketAddr> {
                    bytes: v6.bytes,
                    result: SocketAddr::V6(SocketAddrV6::new(v6.result, port, 0, 0)),
                }),
            }
        } else {
            Err(TLVError(format!(
                "unsupported SocketAddr address family: {}",
                address_family
            )))
        }
    }
}

fn deserialize_ipaddr(stream: &[u8]) -> TLVResult<IpAddr> {
    if stream.len() < (VALUE_OFFSET + 8) {
        return Err(TLVError(format!(
            "stream too short for IP address: {}",
            get_tlv_len(stream)
        )));
    }
    let address_family = deserialize_u16_raw(&stream[VALUE_OFFSET + 2..VALUE_OFFSET + 4]);
    if address_family == AddressFamily::Ipv6 as u16 {
        let maybe = deserialize_ipv6(stream);
        match maybe {
            Ok(result) => Ok(TLVDeserializeOk::<IpAddr> {
                bytes: result.bytes,
                result: IpAddr::V6(result.result),
            }),
            Err(_) => Err(maybe.unwrap_err()),
        }
    } else if address_family == AddressFamily::Ipv4 as u16 {
        let maybe = deserialize_ipv4(stream);
        match maybe {
            Ok(result) => Ok(TLVDeserializeOk::<IpAddr> {
                bytes: result.bytes,
                result: IpAddr::V4(result.result),
            }),
            Err(_) => Err(maybe.unwrap_err()),
        }
    } else {
        Err(TLVError(format!(
            "Unsupported Address Family: {}",
            address_family
        )))
    }
}

#[inline]
fn deserialize_cstring_raw(stream: &[u8]) -> TLVResult<String> {
    if stream[stream.len() - 1] != 0x00 {
        Err(TLVError("Cstring not NULL-terminated".to_string()))
    } else {
        Ok(TLVDeserializeOk::<String> {
            bytes: stream.len() - 1,
            result: String::from_utf8_lossy(&stream[0..stream.len() - 1]).to_string(),
        })
    }
}

fn deserialize_cstring(stream: &[u8]) -> TLVResult<String> {
    let object_length = get_tlv_len(stream);
    if stream.len() < VALUE_OFFSET + 1 {
        return Err(TLVError(format!(
            "stream too short for Cstring: {}",
            get_tlv_len(stream)
        )));
    } else if stream.len() < (get_tlv_len(stream) + VALUE_OFFSET) {
        return Err(TLVError(format!(
            "stream length {} too short for length field {}",
            stream.len(),
            get_tlv_len(stream),
        )));
    }
    let try_string = deserialize_cstring_raw(&stream[VALUE_OFFSET..VALUE_OFFSET + object_length]);
    if try_string.is_err() {
        try_string
    } else {
        Ok(TLVDeserializeOk::<String> {
            bytes: VALUE_OFFSET + object_length,
            result: try_string.unwrap().result,
        })
    }
}

fn deserialize_seqno(stream: &[u8]) -> TLVResult<SequenceNumber> {
    if stream.len() < VALUE_OFFSET + SEQNO_LEN {
        Err(TLVError(format!(
            "stream too short for SequenceNumber: {} vs {}",
            stream.len(),
            SEQNO_LEN
        )))
    } else if get_tlv_len(stream) != SEQNO_LEN {
        Err(TLVError(format!(
            "TLV length {} incorrect for SequenceNumber",
            get_tlv_len(stream),
        )))
    } else {
        // Something goes here...
        Ok(TLVDeserializeOk::<SequenceNumber> {
            bytes: VALUE_OFFSET + SEQNO_LEN,
            result: SequenceNumber {
                reqid: deserialize_u64_raw(&stream[VALUE_OFFSET..VALUE_OFFSET + 8]),
                sessionid: deserialize_u32_raw(&stream[VALUE_OFFSET + 8..VALUE_OFFSET + 12]),
                qid: deserialize_u16_raw(&stream[VALUE_OFFSET + 12..VALUE_OFFSET + 14]),
            },
        })
    }
}
fn deserialize_signature(stream: &[u8]) -> TLVResult<Signature> {
    if stream.len() < VALUE_OFFSET + MIN_SIGNATURE_LEN {
        return Err(TLVError(format!(
            "stream too short for Signature: {} vs {}",
            stream.len(),
            MIN_SIGNATURE_LEN
        )));
    }
    let frame_type = deserialize_u16_raw(&stream[0..2]);
    let frame_len = deserialize_u32_raw(&stream[2..6]) as usize;
    if frame_type != SIGNATURE_FRAME_TYPE {
        Err(TLVError(format!(
            "Signature frame type incorrect: must be {} instead of {}",
            SIGNATURE_FRAME_TYPE, frame_type
        )))
    } else {
        let signature = Signature {
            sign_provider: stream[VALUE_OFFSET],
            sign_type: stream[VALUE_OFFSET + 1],
            signature: Box::new(&stream[VALUE_OFFSET + 2..VALUE_OFFSET + frame_len]),
        };
        if signature.is_valid().is_err() {
            Err(TLVError(format!(
                "Signature information is not valid: {:?} ",
                signature.is_valid().unwrap_err()
            )))
        } else {
            Ok(TLVDeserializeOk::<Signature> {
                bytes: VALUE_OFFSET + frame_len,
                result: signature,
            })
        }
    }
}

fn deserialize_compression(stream: &[u8]) -> TLVResult<Compression> {
    // Right now, we only support stupid, do-nothing compression (compression type 0).
    if stream.len() < VALUE_OFFSET + size_of::<Compression>() {
        return Err(TLVError(format!(
            "stream too short for Compression frame: {}",
            stream.len(),
        )));
    }
    let frame_len = deserialize_u32_raw(&stream[LEN_OFFSET..LEN_OFFSET + 4]) as usize;
    let uncompressed_size = deserialize_u32_raw(&stream[VALUE_OFFSET..VALUE_OFFSET + 4]);
    let compression_type = stream[VALUE_OFFSET + 4];
    if compression_type != 0 {
        return Err(TLVError(format!(
            "unsupported compression type: {}",
            compression_type
        )));
    } else if uncompressed_size != (frame_len - 5) as u32 {
        return Err(TLVError(format!(
            "unsupported compression type: {}",
            compression_type
        )));
    }
    let mut compression = Compression {
        compression_type,
        uncompressed_size,
        data: Box::new(b""),
    };
    if compression.is_valid().is_err() {
        Err(TLVError(format!(
            "Compression frame is not valid: {:?} ",
            compression.is_valid().unwrap_err()
        )))
    } else {
        // Decompression step goes here...
        let decompressed_data = Box::new(&stream[VALUE_OFFSET + 5..VALUE_OFFSET + frame_len]);
        compression.data = decompressed_data;
        Ok(TLVDeserializeOk::<Compression> {
            bytes: VALUE_OFFSET + frame_len,
            result: compression,
        })
    }
}
fn deserialize_encryption(stream: &[u8]) -> TLVResult<Encryption> {
    // Right now, we only support stupid, do-nothing compression (compression type 0).
    if stream.len() < VALUE_OFFSET + 5 {
        return Err(TLVError(format!(
            "stream too short for Encryption frame: {}",
            stream.len(),
        )));
    }
    let frame_length = get_tlv_len(stream);
    let sender_key_len = stream[VALUE_OFFSET] as usize;
    let min_length = VALUE_OFFSET + sender_key_len + 2;
    if stream.len() < min_length {
        return Err(TLVError(format!(
            "stream too short for Encryption frame as formatted(1): {}",
            stream.len(),
        )));
    }
    let receiver_key_len = stream[VALUE_OFFSET + 1 + sender_key_len] as usize;
    let min_length = VALUE_OFFSET + sender_key_len + receiver_key_len + 2;

    if stream.len() < min_length {
        return Err(TLVError(format!(
            "stream too short for Encryption frame as formatted(2): {}, {}, {}",
            stream.len(),
            sender_key_len,
            receiver_key_len
        )));
    }
    let receiver_key_try =
        deserialize_cstring_raw(&stream[VALUE_OFFSET + 1..VALUE_OFFSET + 2 + receiver_key_len]);
    if receiver_key_try.is_err() {
        return Err(TLVError(receiver_key_try.unwrap_err().to_string()));
    }
    let receiver_key_id = receiver_key_try.unwrap().result;
    let receiver_id_len = receiver_key_id.len() + 1;

    let sender_key_try = deserialize_cstring_raw(
        &stream[VALUE_OFFSET + 2 + receiver_id_len
            ..VALUE_OFFSET + 2 + receiver_key_len + sender_key_len],
    );
    if sender_key_try.is_err() {
        return Err(TLVError(sender_key_try.unwrap_err().to_string()));
    }
    let sender_key_id = sender_key_try.unwrap().result;
    let sender_id_len = sender_key_id.len() + 1;

    let mut decrypted = Encryption {
        sender_key_id,
        receiver_key_id,
        data: Box::new(b""),
    };
    if decrypted.is_valid().is_err() {
        Err(TLVError(format!(
            "Encryption frame is not valid: {:?} ",
            decrypted.is_valid().unwrap_err()
        )))
    } else {
        // Decryption step goes here...
        decrypted.data =
            Box::new(&stream[VALUE_OFFSET + 2 + sender_id_len + receiver_id_len..frame_length]);
        Ok(TLVDeserializeOk::<Encryption> {
            bytes: min_length + decrypted.data.len(),
            result: decrypted,
        })
    }
}

//=====================================================================
//
//  Serialization code starts below.
//  We take data from an in-memory form to a serialized form suitable
//  for putting in a packet.
//
//=====================================================================

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

fn serialize_ipv4_w_port(stream: &mut Vec<u8>, itype: u16, item: Ipv4Addr, port: u16) {
    serialize_u16_raw(stream, itype);
    serialize_u32_raw(stream, size_of::<Ipv4Addr>() as u32 + 4);
    serialize_u16_raw(stream, port); // port
    serialize_u16_raw(stream, AddressFamily::Ipv4 as u16); // Address family
    for octet in item.octets() {
        stream.push(octet);
    }
}
fn serialize_ipv4(stream: &mut Vec<u8>, itype: u16, item: Ipv4Addr) {
    serialize_ipv4_w_port(stream, itype, item, 0x00u16)
}
fn serialize_ipv6_w_port(stream: &mut Vec<u8>, itype: u16, item: Ipv6Addr, port: u16) {
    serialize_u16_raw(stream, itype); // Type
    serialize_u32_raw(stream, size_of::<Ipv6Addr>() as u32 + 4); // Length
    serialize_u16_raw(stream, port);
    serialize_u16_raw(stream, AddressFamily::Ipv6 as u16); // Address family
    for octet in item.octets() {
        stream.push(octet);
    }
}
fn serialize_ipv6(stream: &mut Vec<u8>, itype: u16, item: Ipv6Addr) {
    serialize_ipv6_w_port(stream, itype, item, 0x00u16)
}

fn serialize_ipaddr(stream: &mut Vec<u8>, itype: u16, item: IpAddr) {
    match item {
        IpAddr::V4(v4) => serialize_ipv4(stream, itype, v4),
        IpAddr::V6(v6) => serialize_ipv6(stream, itype, v6),
    }
}

fn serialize_socketaddr(stream: &mut Vec<u8>, itype: u16, item: SocketAddr) {
    match item.ip() {
        IpAddr::V4(v4) => serialize_ipv4_w_port(stream, itype, v4, item.port()),
        IpAddr::V6(v6) => serialize_ipv6_w_port(stream, itype, v6, item.port()),
    }
}

fn serialize_cstring(stream: &mut Vec<u8>, itype: u16, item: &String) {
    serialize_u16_raw(stream, itype);
    let length = item.len() + 1;
    serialize_u32_raw(stream, length as u32);
    for byte in item.as_bytes() {
        stream.push(*byte);
    }
    stream.push(0x00);
}
fn serialize_seqno(stream: &mut Vec<u8>, itype: u16, item: &SequenceNumber) {
    serialize_u16_raw(stream, itype);
    serialize_u32_raw(stream, SEQNO_LEN as u32);
    serialize_u64_raw(stream, item.reqid);
    serialize_u32_raw(stream, item.sessionid);
    serialize_u16_raw(stream, item.qid);
}
fn serialize_signature(stream: &mut Vec<u8>, itype: u16, item: &Signature) {
    serialize_u16_raw(stream, itype);
    let len = size_of::<u8>() + size_of::<u8>() + item.signature.len();
    serialize_u32_raw(stream, len as u32);
    stream.push(item.sign_provider);
    stream.push(item.sign_type);
    stream.append(&mut item.signature.to_vec());
}
fn serialize_compression(stream: &mut Vec<u8>, itype: u16, item: &Compression) {
    serialize_u16_raw(stream, itype);
    let len = size_of::<u8>() + size_of::<u32>() + item.data.len();
    serialize_u32_raw(stream, len as u32);
    // Should be zero until we implement compression
    serialize_u32_raw(stream, item.uncompressed_size);
    stream.push(item.compression_type);
    // We should append the compressed data instead of the uncompressed data...
    stream.append(&mut item.data.to_vec());
}
fn serialize_encryption(stream: &mut Vec<u8>, itype: u16, item: &Encryption) {
    serialize_u16_raw(stream, itype);
    let data_vec = &mut item.data.to_vec();
    let len =
        VALUE_OFFSET + 4 + item.receiver_key_id.len() + item.sender_key_id.len() + data_vec.len();

    serialize_u32_raw(stream, len as u32);
    stream.push((item.receiver_key_id.len() + 1) as u8);
    for byte in item.receiver_key_id.as_bytes() {
        stream.push(*byte);
    }
    stream.push(0x00u8);
    stream.push((item.sender_key_id.len() + 1) as u8);
    for byte in item.sender_key_id.as_bytes() {
        stream.push(*byte);
    }
    stream.push(0x00u8);
    // We should append the decrypted data instead of the "encrypted" data...
    stream.append(&mut item.data.to_vec());
}
//=====================================================================
//
//  Unit tests start below
//
//=====================================================================

#[cfg(test)]
// Should these be UNIX-only tests and have a different mod for non-UNIX specific tests?
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_u8() {
        let stream = &mut Vec::new();
        let test_data = 255u8; // Not the same as the type or length
        serialize_u8(stream, 1, test_data);
        let result = deserialize_u8(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len())
    }

    #[test]
    fn test_u16() {
        let stream = &mut Vec::new();
        let test_data = 0xeffe; // Every byte is different
        serialize_u16(stream, 1, test_data);
        let result = deserialize_u16(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len())
    }
    #[test]
    fn test_u24() {
        let stream = &mut Vec::new();
        let test_data = 0xedbeefu32; // Every byte is different
        serialize_u24(stream, 1, test_data);
        let result = deserialize_u24(&stream);
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len())
    }
    #[test]
    fn test_u32() {
        let stream = &mut Vec::new();
        let test_data = 0xfeedbeefu32; // Every byte is different
        serialize_u32(stream, 1, test_data);
        let result = deserialize_u32(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len())
    }
    #[test]
    fn test_u64() {
        let stream = &mut Vec::new();
        let test_data = 0xfeedbeefb1e55ed1; // Every byte is different
        serialize_u64(stream, 1, test_data);
        let result = deserialize_u64(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len())
    }

    #[test]
    fn test_ipv4() {
        let stream = &mut Vec::new();
        let test_addr = IpAddr::from_str("1.2.3.4").unwrap();

        match test_addr {
            IpAddr::V6(_) => assert!(false),
            IpAddr::V4(addr) => {
                serialize_ipv4(stream, 1, addr);
                let result = deserialize_ipv4(&stream);
                assert!(result.is_ok());
                assert_eq!(result.unwrap().result, addr);
                let result = deserialize_ipaddr(&stream);
                assert!(result.is_ok());
                let unwrapped = result.unwrap();
                assert_eq!(unwrapped.result, addr);
                assert_eq!(unwrapped.bytes, stream.len());
                assert_eq!(unwrapped.bytes, VALUE_OFFSET + 8);
            }
        }
    }
    #[test]
    fn test_ipv6() {
        let stream = &mut Vec::new();
        let test_addr = IpAddr::from_str("2000::1:2:3").unwrap();

        match test_addr {
            IpAddr::V4(_) => assert!(false),
            IpAddr::V6(addr) => {
                serialize_ipv6(stream, 1, addr);
                let result = deserialize_ipv6(&stream);
                assert!(result.is_ok());
                let unwrapped = result.unwrap();
                assert_eq!(unwrapped.result, addr);
                assert_eq!(unwrapped.bytes, VALUE_OFFSET + 20);
                let result = deserialize_ipaddr(&stream);
                assert!(result.is_ok());
                let unwrapped = result.unwrap();
                assert_eq!(unwrapped.result, test_addr);
                assert_eq!(unwrapped.bytes, stream.len());
            }
        }
    }
    #[test]
    fn test_ipaddr() {
        let stream = &mut Vec::new();
        let test_addr = IpAddr::from_str("2000::1:2:3").unwrap();

        serialize_ipaddr(stream, 1, test_addr);
        let result = deserialize_ipv6(&stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().result, test_addr);
        let result = deserialize_ipv6(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(IpAddr::V6(unwrapped.result), test_addr);
        assert_eq!(unwrapped.bytes, stream.len());
        assert_eq!(unwrapped.bytes, VALUE_OFFSET + 20);
    }
    #[test]
    fn test_socketaddr() {
        let stream = &mut Vec::new();
        let test_addr = SocketAddr::from_str("[2000::1:2:3]:42").unwrap();

        serialize_socketaddr(stream, 1, test_addr);
        let result = deserialize_socketaddr(&stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().result, test_addr);
        let result = deserialize_socketaddr(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_addr);
        assert_eq!(unwrapped.bytes, stream.len());
        assert_eq!(unwrapped.bytes, VALUE_OFFSET + 20);
    }
    #[test]
    fn test_cstring() {
        let stream = &mut Vec::new();
        let test_string = "Hello, world!".to_string();

        serialize_cstring(stream, 1, &test_string);
        let result = deserialize_cstring(&stream);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().result, test_string);
        let result = deserialize_cstring(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_string);
        assert_eq!(unwrapped.bytes, stream.len());
        assert_eq!(unwrapped.bytes, VALUE_OFFSET + test_string.len() + 1);
        let stream_len = stream.len();
        stream[stream_len - 1] = 0x40; // A blank...
        let result = deserialize_cstring(&stream);
        assert!(result.is_err());
        let err_msg = result.expect_err("REASON").to_string();
        assert_eq!(err_msg, "TLV error: Cstring not NULL-terminated");
    }
    #[test]
    fn test_seqno() {
        let stream = &mut Vec::new();
        let test_data = SequenceNumber {
            reqid: 60223,
            sessionid: 31415,
            qid: 42,
        };
        serialize_seqno(stream, 1, &test_data);
        let result = deserialize_seqno(&stream);
        // assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len());
        assert_eq!(unwrapped.bytes, VALUE_OFFSET + SEQNO_LEN);
    }
    #[test]
    fn test_signature() {
        let stream = &mut Vec::new();
        let test_data = Signature {
            sign_provider: 0,
            sign_type: 0,
            signature: Box::new(b"Ford Prefect"),
        };
        serialize_signature(stream, 1, &test_data);
        let result = deserialize_signature(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len());
    }
    #[test]
    fn test_compression() {
        let stream = &mut Vec::new();
        let data = b"Zaphod Beeblebrox";
        let test_data = Compression {
            compression_type: 0,
            uncompressed_size: data.len() as u32,
            data: Box::new(data),
        };
        serialize_compression(stream, 1, &test_data);
        let result = deserialize_compression(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len());
    }
    #[test]
    fn test_encryption() {
        let stream = &mut Vec::new();
        let data = b"Slarty Bartfast";
        let test_data = Encryption {
            sender_key_id: "me".to_string(),
            receiver_key_id: "you".to_string(),
            data: Box::new(data),
        };
        serialize_encryption(stream, 1, &test_data);
        let result = deserialize_encryption(&stream);
        assert!(result.is_ok());
        let unwrapped = result.unwrap();
        assert_eq!(unwrapped.result, test_data);
        assert_eq!(unwrapped.bytes, stream.len());
    }
}
