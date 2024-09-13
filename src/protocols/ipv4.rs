use std::{
    collections::LinkedList,
    sync::{Arc, Mutex, Weak},
};

use anyhow::ensure;
use log::debug;

use crate::{
    devices::NetDevice,
    transport::{icmp, TransportProtocolNumber},
};

use super::{NetInterfaceFamily, NetProtocolContext, NetProtocolType};

const IPV4_HEADER_MIN_LENGTH: u8 = 20;
const IPV4_HEADER_MAX_LENGTH: u8 = 60;
const IPV4_VERSION: u8 = 4;
pub const IPV4_ADDR_ANY: Ipv4Address = Ipv4Address(0x00000000); // 0.0.0.0
pub const IPV4_ADDR_BROADCAST: Ipv4Address = Ipv4Address(0xffffffff); // 255.255.255.255

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address(pub u32);

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

impl ToString for Ipv4Address {
    fn to_string(&self) -> String {
        let octets = [
            (self.0 >> 24) & 0xff,
            (self.0 >> 16) & 0xff,
            (self.0 >> 8) & 0xff,
            self.0 & 0xff,
        ];
        format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
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
        ensure!(
            self.version() == IPV4_VERSION,
            "invalid version: {}",
            self.version()
        );
        ensure!(
            self.header_length() >= IPV4_HEADER_MIN_LENGTH,
            "ipv4 header too short: {}",
            self.header_length()
        );
        ensure!(
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
        ensure!(checksum == 0, "invalid checksum: 0x{:04x}", checksum);
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

    pub fn includes(&self, unicast: Ipv4Address) -> bool {
        self.netmask.0 & self.unicast.0 == self.netmask.0 & unicast.0
    }
}

#[derive(Clone, Debug)]
pub struct IpRouter {
    pub interfaces: LinkedList<IpRoute>,
}

impl IpRouter {
    pub fn new() -> Self {
        IpRouter {
            interfaces: LinkedList::new(),
        }
    }

    pub fn register(&mut self, route: IpRoute) {
        self.interfaces.push_back(route);
    }

    pub fn route(&self, dst: Ipv4Address) -> Option<Arc<Ipv4Interface>> {
        for route in self.interfaces.iter() {
            if dst == route.unicast {
                return Some(route.interface.clone());
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
pub struct IpRoute {
    unicast: Ipv4Address,
    pub interface: Arc<Ipv4Interface>,
}

impl IpRoute {
    pub fn new(unicast: Ipv4Address, interface: Arc<Ipv4Interface>) -> Self {
        IpRoute { unicast, interface }
    }
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

pub fn output(
    context: &mut NetProtocolContext,
    protocol: TransportProtocolNumber,
    data: &[u8],
    src: Ipv4Address,
    dst: Ipv4Address,
) -> anyhow::Result<()> {
    if src == IPV4_ADDR_ANY {
        anyhow::bail!("ip routing not implemented");
    }

    let Some(interface) = context.router.route(src) else {
        anyhow::bail!("no route found, src: {}", src.to_string());
    };
    anyhow::ensure!(
        interface.includes(dst) || dst == IPV4_ADDR_BROADCAST,
        "incoming packet not routed properly"
    );

    let Some(output_device) = interface.device.as_ref() else {
        anyhow::bail!(
            "device not found, interface: {}",
            interface.unicast.to_string()
        );
    };
    let output_device = output_device.upgrade().unwrap();
    let mut output_device = output_device.lock().unwrap();
    if output_device.mtu < data.len() {
        anyhow::bail!(
            "packet too long, dev: {}, len: {}, mtu: {}",
            output_device.name,
            data.len(),
            output_device.mtu
        );
    }

    let id = context.id_manager.next();
    let mut output_data = create_ip_header(id, protocol, src, dst, data);
    output_data.extend(data);
    debug!("ipv4 packet transmitted, {:?}", output_data);
    output_device.transmit(
        &output_data,
        NetProtocolType::Ipv4,
        [0xff; crate::devices::NET_DEVICE_ADDR_LEN],
    )
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

pub fn handle_input(
    interface: Arc<Ipv4Interface>,
    context: &mut NetProtocolContext,
    data: &[u8],
) -> anyhow::Result<()> {
    let header = Ipv4Header::try_from(data.as_ref())?;
    header.validate()?;
    // let Some(interface) = device.get_interface(NetInterfaceFamily::Ipv4) else {
    //     debug!("no ipv4 interface, dev: {}", device.name);
    //     return Ok(());
    // };
    if header.dst != interface.unicast
        && header.dst != interface.broadcast
        && header.dst != IPV4_ADDR_BROADCAST
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
        TransportProtocolNumber::Icmp => {
            icmp::handle_input(context, interface, payload, header.src, header.dst)?
        }
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
}
