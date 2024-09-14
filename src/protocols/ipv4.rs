use std::{
    collections::LinkedList,
    sync::{Arc, Mutex, Weak},
};

use log::debug;

use crate::{
    devices::{ethernet::MAC_ADDRESS_BROADCAST, NetDevice, NET_DEVICE_FLAG_NEED_ARP},
    protocols::arp::{resolve_arp, ArpCacheState},
    transport::{icmp, TransportProtocolNumber},
};

use super::{NetInterfaceFamily, NetProtocolContext, NetProtocolType};

const IPV4_HEADER_MIN_LENGTH: u8 = 20;
const IPV4_HEADER_MAX_LENGTH: u8 = 60;
const IPV4_VERSION: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Address(pub u32);

impl Ipv4Address {
    pub const ANY: Ipv4Address = Ipv4Address(0x00000000); // 0.0.0.0
    pub const BROADCAST: Ipv4Address = Ipv4Address(0xffffffff); // 255.255.255.255
}

impl std::ops::BitAnd for Ipv4Address {
    type Output = Ipv4Address;

    fn bitand(self, rhs: Self) -> Self::Output {
        Ipv4Address(self.0 & rhs.0)
    }
}

impl From<&[u8; 4]> for Ipv4Address {
    fn from(value: &[u8; 4]) -> Self {
        Ipv4Address(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }
}

impl TryFrom<&str> for Ipv4Address {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let octets: Vec<&str> = value.split('.').collect();
        if octets.len() != 4 {
            anyhow::bail!("invalid ipv4 address: {}", value);
        }
        let mut addr = 0;
        for octet in octets {
            let octet: u8 = octet.parse()?;
            addr = (addr << 8) | u32::from(octet);
        }
        Ok(Ipv4Address(addr))
    }
}

impl std::fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let octets = [
            (self.0 >> 24) & 0xff,
            (self.0 >> 16) & 0xff,
            (self.0 >> 8) & 0xff,
            self.0 & 0xff,
        ];
        write!(f, "{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    }
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    version_header_length: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: TransportProtocolNumber,
    pub header_checksum: u16,
    pub src: Ipv4Address,
    pub dst: Ipv4Address,
}

impl Ipv4Header {
    pub fn version(&self) -> u8 {
        self.version_header_length >> 4
    }

    pub fn header_length(&self) -> u8 {
        (self.version_header_length & 0x0f) * 4
    }

    pub fn flags(&self) -> u8 {
        (self.flags_fragment_offset >> 13) as u8
    }

    pub fn fragment_offset(&self) -> u16 {
        self.flags_fragment_offset & 0x1fff
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version() == IPV4_VERSION,
            "invalid version: {}",
            self.version()
        );
        anyhow::ensure!(
            self.header_length() >= IPV4_HEADER_MIN_LENGTH,
            "ipv4 header too short: {}",
            self.header_length()
        );
        anyhow::ensure!(
            self.header_length() < IPV4_HEADER_MAX_LENGTH,
            "ipv4 header too long: {}",
            self.header_length()
        );
        // TODO: check total_length is match the actual length
        if self.flags() & 0x1 > 0 || self.fragment_offset() & 0x1fff > 0 {
            anyhow::bail!("fragmentation is not supported");
        }
        self.validate_checksum()?;
        Ok(())
    }

    fn validate_checksum(&self) -> anyhow::Result<()> {
        let data = self.to_bytes();
        let checksum = crate::utils::calculate_checksum(&data);
        anyhow::ensure!(checksum == 0, "invalid checksum: {:04x}", checksum);
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.version_header_length,
            self.tos,
            (self.total_length >> 8) as u8,
            self.total_length as u8,
            (self.identification >> 8) as u8,
            self.identification as u8,
            (self.flags_fragment_offset >> 8) as u8,
            self.flags_fragment_offset as u8,
            self.ttl,
            self.protocol as u8,
            (self.header_checksum >> 8) as u8,
            self.header_checksum as u8,
            (self.src.0 >> 24) as u8,
            (self.src.0 >> 16) as u8,
            (self.src.0 >> 8) as u8,
            self.src.0 as u8,
            (self.dst.0 >> 24) as u8,
            (self.dst.0 >> 16) as u8,
            (self.dst.0 >> 8) as u8,
            self.dst.0 as u8,
        ]
    }
}

impl TryFrom<&[u8]> for Ipv4Header {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let protocol = TransportProtocolNumber::try_from(value[9])?;
        Ok(Ipv4Header {
            version_header_length: value[0],
            tos: value[1],
            total_length: u16::from_be_bytes([value[2], value[3]]),
            identification: u16::from_be_bytes([value[4], value[5]]),
            flags_fragment_offset: u16::from_be_bytes([value[6], value[7]]),
            ttl: value[8],
            protocol,
            header_checksum: u16::from_be_bytes([value[10], value[11]]),
            src: Ipv4Address(u32::from_be_bytes([
                value[12], value[13], value[14], value[15],
            ])),
            dst: Ipv4Address(u32::from_be_bytes([
                value[16], value[17], value[18], value[19],
            ])),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4Interface {
    pub family: NetInterfaceFamily,
    pub unicast: Ipv4Address,
    pub netmask: Ipv4Address,
    pub broadcast: Ipv4Address,
    pub device: Option<Weak<Mutex<NetDevice>>>,
}

impl Ipv4Interface {
    pub fn new(unicast: Ipv4Address, netmask: Ipv4Address, device: Arc<Mutex<NetDevice>>) -> Self {
        let broadcast = Ipv4Address(unicast.0 & 0xffffff00 | !netmask.0 & 0xff);
        Ipv4Interface {
            family: NetInterfaceFamily::Ipv4,
            unicast,
            netmask,
            broadcast,
            device: Some(Arc::downgrade(&device)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4Router {
    interfaces: LinkedList<IpRoute>,
}

impl Ipv4Router {
    pub fn new() -> Self {
        Ipv4Router {
            interfaces: LinkedList::new(),
        }
    }

    pub fn register(&mut self, network: Ipv4Address, interface: Arc<Ipv4Interface>) {
        self.interfaces.push_back(IpRoute {
            network,
            netmask: interface.netmask,
            interface,
            next_hop: None,
        });
    }

    pub fn register_default(&mut self, interface: Arc<Ipv4Interface>, gateway: Ipv4Address) {
        self.interfaces.push_front(IpRoute {
            network: Ipv4Address::ANY,
            netmask: Ipv4Address::ANY,
            interface,
            next_hop: Some(gateway),
        });
    }

    fn lookup(&self, dst: Ipv4Address) -> Option<IpRoute> {
        let mut candidate: Option<&IpRoute> = None;
        for route in self.interfaces.iter() {
            if dst & route.netmask == route.network
                && (candidate.is_none() || route.netmask.0 > candidate.as_ref().unwrap().netmask.0)
            {
                candidate = Some(route);
            }
        }
        candidate.cloned()
    }
}

#[derive(Clone, Debug)]
struct IpRoute {
    network: Ipv4Address,
    netmask: Ipv4Address,
    interface: Arc<Ipv4Interface>,
    next_hop: Option<Ipv4Address>,
}

#[derive(Clone, Debug)]
pub struct Ipv4IdGenerator {
    id: u16,
}

impl Ipv4IdGenerator {
    pub fn new() -> Self {
        Ipv4IdGenerator { id: 0 }
    }

    pub fn next(&mut self) -> u16 {
        let id = self.id;
        self.id = self.id.wrapping_add(1);
        id
    }
}

#[tracing::instrument(skip(context, protocol, data))]
pub fn send(
    context: &mut NetProtocolContext,
    protocol: TransportProtocolNumber,
    data: &[u8],
    src: Ipv4Address,
    dst: Ipv4Address,
) -> anyhow::Result<()> {
    let Some(route) = context.router.lookup(dst) else {
        anyhow::bail!("no route found, dst: {}", dst.to_string());
    };
    let interface = route.interface;
    let Some(device) = interface.device.as_ref() else {
        anyhow::bail!(
            "device not found, interface: {}",
            interface.unicast.to_string()
        );
    };
    let device = device.upgrade().unwrap();
    let mut device = device.lock().unwrap();

    anyhow::ensure!(
        src != Ipv4Address::ANY || dst != Ipv4Address::BROADCAST,
        "source address is required for broadcast packet"
    );
    anyhow::ensure!(
        src == Ipv4Address::ANY || src == interface.unicast,
        "unable to send packet with the source address, src: {}, interface: {}",
        src.to_string(),
        interface.unicast.to_string()
    );
    anyhow::ensure!(
        data.len() < device.mtu,
        "packet too long, len: {}, mtu: {}",
        data.len(),
        device.mtu
    );

    let id = context.id_manager.next();
    let mut output_data = create_ip_header(id, protocol, interface.unicast, dst, data);
    output_data.extend(data);

    let dst_hw_address = if device.flags & NET_DEVICE_FLAG_NEED_ARP != 0 {
        // Handle broadcast address
        if dst == interface.broadcast || dst == Ipv4Address::BROADCAST {
            MAC_ADDRESS_BROADCAST
        } else {
            // For example, packet to default gateway, destination IPv4 address and next hop IPv4 address are different.
            let next_hop = if let Some(next_hop) = route.next_hop {
                next_hop
            } else {
                dst
            };
            let ArpCacheState::Resolved(hw_address) =
                resolve_arp(&mut device, &interface, &mut context.arp_cache, next_hop)?
            else {
                debug!("no arp cache hit, dst: {}", next_hop.to_string());
                return Ok(());
            };
            hw_address
        }
    } else {
        MAC_ADDRESS_BROADCAST
    };
    device.send(&output_data, NetProtocolType::Ipv4, dst_hw_address)
}

fn create_ip_header(
    id: u16,
    protocol: TransportProtocolNumber,
    src: Ipv4Address,
    dst: Ipv4Address,
    data: &[u8],
) -> Vec<u8> {
    let total_length = IPV4_HEADER_MIN_LENGTH as u16 + data.len() as u16;
    let header = Ipv4Header {
        version_header_length: 0x45, // version 4, header length 20(= 5 * 4) bytes
        tos: 0,
        total_length,
        identification: id,
        flags_fragment_offset: 0,
        ttl: 64,
        protocol,
        header_checksum: 0,
        src,
        dst,
    };
    let mut bytes = header.to_bytes();
    let checksum = crate::utils::calculate_checksum(&bytes);
    bytes[10] = (checksum >> 8) as u8;
    bytes[11] = checksum as u8;
    bytes
}

#[tracing::instrument(skip_all)]
pub fn recv(
    context: &mut NetProtocolContext,
    interface: Arc<Ipv4Interface>,
    data: &[u8],
) -> anyhow::Result<()> {
    let header = Ipv4Header::try_from(data)?;
    header.validate()?;
    if header.dst != interface.unicast
        && header.dst != interface.broadcast
        && header.dst != Ipv4Address::BROADCAST
    {
        return Ok(());
    }
    debug!(
        "ipv4 packet received, src:{}, dst: {}, interface: {:?}",
        header.src.to_string(),
        header.dst.to_string(),
        interface
    );

    let payload = &data[header.header_length() as usize..data.len()];
    match header.protocol {
        TransportProtocolNumber::Icmp => icmp::recv(context, payload, header.src, header.dst)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_header() {
        let data = [
            0x45, 0x00, 0x00, 0x30, 0x00, 0x80, 0x00, 0x00, 0xff, 0x01, 0xbd, 0x4a, 0x7f, 0x00,
            0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x35, 0x64, 0x00, 0x80, 0x00, 0x01,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x21, 0x40, 0x23, 0x24,
            0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29,
        ];
        let header = Ipv4Header::try_from(data.as_ref()).unwrap();
        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_match_lookup() {
        let mut router = Ipv4Router::new();
        let interface = Arc::new(Ipv4Interface::new(
            Ipv4Address::try_from("192.0.0.1").unwrap(),
            Ipv4Address::try_from("255.0.0.0").unwrap(),
            Arc::new(Mutex::new(NetDevice::null())),
        ));
        router.register(
            Ipv4Address::try_from("192.0.0.0").unwrap(),
            interface.clone(),
        );
        let dst = Ipv4Address::try_from("192.0.0.2").unwrap();
        assert_eq!(
            router.lookup(dst).unwrap().interface.unicast,
            interface.unicast
        );
    }

    #[test]
    fn test_match_lookup_longest() {
        let mut router = Ipv4Router::new();
        let eth0 = Arc::new(Ipv4Interface::new(
            Ipv4Address::try_from("192.0.0.1").unwrap(),
            Ipv4Address::try_from("255.0.0.0").unwrap(),
            Arc::new(Mutex::new(NetDevice::null())),
        ));
        router.register(Ipv4Address::try_from("192.0.0.0").unwrap(), eth0.clone());
        let eth1 = Arc::new(Ipv4Interface::new(
            Ipv4Address::try_from("192.0.1.1").unwrap(),
            Ipv4Address::try_from("255.255.0.0").unwrap(),
            Arc::new(Mutex::new(NetDevice::null())),
        ));
        router.register(Ipv4Address::try_from("192.0.0.0").unwrap(), eth1.clone());
        let dst = Ipv4Address::try_from("192.0.1.2").unwrap();
        assert_eq!(router.lookup(dst).unwrap().interface.unicast, eth1.unicast);
    }

    #[test]
    fn test_match_lookup_default() {
        let mut router = Ipv4Router::new();
        let eth0 = Arc::new(Ipv4Interface::new(
            Ipv4Address::try_from("192.0.0.1").unwrap(),
            Ipv4Address::try_from("255.255.0.0").unwrap(),
            Arc::new(Mutex::new(NetDevice::null())),
        ));
        let gateway = Ipv4Address::from(&[192, 0, 0, 1]);
        router.register(Ipv4Address::from(&[192, 0, 0, 0]), eth0.clone());
        router.register_default(eth0, gateway);
        let dst = Ipv4Address::from(&[8, 8, 8, 8]);
        assert_eq!(router.lookup(dst).unwrap().interface.unicast, gateway);
    }
}
