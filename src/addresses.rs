use std::convert::TryFrom;
use std::fmt;
use std::fmt::Formatter;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

#[derive(Copy, Clone, PartialEq, Debug)]
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

pub trait IsAnAddress {
    fn addr_family(&self) -> AddressFamily;
}
impl IsAnAddress for Ipv4Addr {
    fn addr_family(&self) -> AddressFamily {
        AddressFamily::Ipv4
    }
}
impl IsAnAddress for Ipv6Addr {
    fn addr_family(&self) -> AddressFamily {
        AddressFamily::Ipv6
    }
}
impl IsAnAddress for Mac48 {
    fn addr_family(&self) -> AddressFamily {
        AddressFamily::Mac48
    }
}
impl IsAnAddress for Mac64 {
    fn addr_family(&self) -> AddressFamily {
        AddressFamily::Mac64
    }
}
impl IsAnAddress for IpAddr {
    fn addr_family(&self) -> AddressFamily {
        match self {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }
}
impl IsAnAddress for NetAddress {
    fn addr_family(&self) -> AddressFamily {
        match self {
            NetAddress::Ipv4(_) => AddressFamily::Ipv4,
            NetAddress::Ipv6(_) => AddressFamily::Ipv6,
            NetAddress::Mac48(_) => AddressFamily::Mac48,
            NetAddress::Mac64(_) => AddressFamily::Mac64,
        }
    }
}
impl IsAnAddress for SocketAddr {
    fn addr_family(&self) -> AddressFamily {
        self.ip().addr_family()
    }
}

#[derive(Clone, PartialEq, Debug)]
// 64-bit MAC address
pub struct Mac64 {
    octets: [u8; 8],
}

#[derive(Clone, PartialEq, Debug)]
// 48-bit MAC address
pub struct Mac48 {
    octets: [u8; 6],
}

#[derive(Clone, PartialEq, Debug)]
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
    fn octets(&self) -> Vec<u8> {
        // There are lifetime issues in this code...
        match self {
            NetAddress::Ipv4(addr) => Vec::from(&addr.octets()[..]),
            NetAddress::Ipv6(addr) => Vec::from(&addr.octets()[..]),
            NetAddress::Mac48(addr) => Vec::from(&addr.octets[..]),
            NetAddress::Mac64(addr) => Vec::from(&addr.octets[..]),
        }
    }
}
impl fmt::Display for NetAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NetAddress::Ipv4(addr) => write!(f, "{}", addr),
            NetAddress::Ipv6(addr) => write!(f, "{}", addr),
            NetAddress::Mac48(addr) => write!(f, "{:?}", addr.octets),
            NetAddress::Mac64(addr) => write!(f, "{:?}", addr.octets),
        }
    }
}
//=====================================================================
//
//  Unit tests start below
//
//=====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v4() {
        let addr_str = "42.42.42.42";
        let ipaddr = IpAddr::from_str(addr_str).unwrap();
        match ipaddr {
            IpAddr::V6(_) => assert!(false),
            IpAddr::V4(addr) => {
                let v4 = NetAddress::Ipv4(addr);
                assert_eq!(v4.family(), ipaddr.addr_family());
                assert_eq!(v4.to_string(), addr_str);
                assert_eq!(v4, NetAddress::try_from(&v4.octets()[..]).unwrap());
                assert_eq!(
                    v4.addr_family(),
                    NetAddress::try_from(&v4.octets()[..])
                        .unwrap()
                        .addr_family()
                )
            }
        }
    }

    #[test]
    fn test_v6() {
        let addr_str = "::1";
        let ipaddr = IpAddr::from_str(addr_str).unwrap();
        match ipaddr {
            IpAddr::V6(addr) => {
                let v6 = NetAddress::Ipv6(addr);
                assert_eq!(v6.family(), ipaddr.addr_family());
                assert_eq!(v6.to_string(), addr_str);
                assert_eq!(v6, NetAddress::try_from(&v6.octets()[..]).unwrap());
                assert_eq!(
                    v6.addr_family(),
                    NetAddress::try_from(&v6.octets()[..])
                        .unwrap()
                        .addr_family()
                )
            }
            IpAddr::V4(_) => assert!(false),
        }
    }
    #[test]
    fn test_address_family() {
        for item in [
            AddressFamily::Ipv4,
            AddressFamily::Ipv6,
            AddressFamily::Mac48,
            AddressFamily::Mac64,
        ] {
            assert_eq!(item, AddressFamily::try_from(item as u16).unwrap());
            assert_ne!(format!("{:?}", item), "");
        }
        let bad_stuff = AddressFamily::try_from(42u16);
        let err_msg = format!("{:?}", bad_stuff);
        assert_eq!(err_msg, "Err(())".to_string());
    }
}
