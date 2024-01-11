use std::convert::TryFrom;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Copy, Clone)]
// From https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
pub enum AddressFamily {
    Ipv4 = 1,
    Ipv6 = 2,
    Mac48 = 16389,
    Mac64 = 16390,
}
impl TryFrom<u16> for AddressFamily {
    type Error = ();
    fn try_from(family: u16) -> Result<Self, Self::Error> {
        match family {
            x if x == AddressFamily::Ipv4 as u16 => Ok(AddressFamily::Ipv4),
            x if x == AddressFamily::Ipv6 as u16 => Ok(AddressFamily::Ipv6),
            x if x == AddressFamily::Mac48 as u16 => Ok(AddressFamily::Mac48),
            x if x == AddressFamily::Mac64 as u16 => Ok(AddressFamily::Mac64),
            _ => Err(()),
        }
    }
}

#[derive(Clone)]
// 64-bit MAC address
pub struct Mac64 {
    octets: [u8; 8],
}

#[derive(Clone)]
// 48-bit MAC address
pub struct Mac48 {
    octets: [u8; 6],
}

#[derive(Clone)]
pub enum NetAddress {
    Mac48(Mac48),
    Mac64(Mac64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}
impl TryFrom<&[u8]> for NetAddress {
    type Error = ();
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match bytes.len() {
            len if len == size_of::<Ipv4Addr>() => Ok(NetAddress::Ipv4(Ipv4Addr::from([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]))),
            len if len == size_of::<Ipv6Addr>() => Ok(NetAddress::Ipv6(Ipv6Addr::from([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]))),
            len if len == size_of::<Mac48>() => Ok(NetAddress::Mac48(Mac48 {
                octets: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
            })),
            len if len == size_of::<Mac64>() => Ok(NetAddress::Mac64(Mac64 {
                octets: [
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ],
            })),
            _ => Err(()),
        }
    }
}
impl NetAddress {
    fn family(&self) -> AddressFamily {
        match self {
            NetAddress::Ipv4(_) => AddressFamily::Ipv4,
            NetAddress::Ipv6(_) => AddressFamily::Ipv6,
            NetAddress::Mac48(_) => AddressFamily::Mac48,
            NetAddress::Mac64(_) => AddressFamily::Mac64,
        }
    }
    // fn octets(&self) -> Box<&[u8]> {
    //     // There are lifetime issues in this code...
    //     match self {
    //         NetAddress::Ipv4(addr) => Box::from(&addr.clone().octets()[..]),
    //         NetAddress::Ipv6(addr) => Box::from(&addr.octets()[..]),
    //         NetAddress::Mac48(addr) => return Box::from(&addr.octets[..]),
    //         NetAddress::Mac64(addr) => return Box::from(&addr.octets[..]),
    //     }
    // }
}
