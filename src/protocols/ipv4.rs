use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use anyhow::ensure;

use crate::devices::NetDevice;

use super::{NetInterfaceFamily, NetProtocol, ProtocolType};

const IPV4_HEADER_MIN_LENGTH: u8 = 20;
const IPV4_HEADER_MAX_LENGTH: u8 = 60;
const IPV4_VERSION: u8 = 4;
pub const IPV4_ADDR_BROADCAST: Ipv4Address = Ipv4Address(0xffffffff); // 255.255.255.255

#[derive(Clone, Debug)]
pub struct Ipv4QueueEntry {
    pub data: Vec<u8>,
    pub device: Arc<NetDevice>,
}

impl NetProtocol {
    pub fn ipv4() -> Self {
        NetProtocol {
            protocol_type: ProtocolType::Ipv4,
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

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
    pub protocol: u8,
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
        let mut sum = data
            .chunks(2)
            .map(|x| u16::from_be_bytes([x[0], x[1]]) as u32)
            .sum::<u32>();
        while sum.checked_shr(16).unwrap_or(0) != 0 {
            sum = (sum & 0xffff) + sum.checked_shr(16).unwrap_or(0);
        }
        ensure!(sum == 0xffff, "invalid checksum: 0x{:04x}", !sum);
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
            self.protocol,
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

impl From<&[u8]> for Ipv4Header {
    fn from(value: &[u8]) -> Self {
        Ipv4Header {
            version_header_length: value[0],
            tos: value[1],
            total_length: u16::from_be_bytes([value[2], value[3]]),
            identification: u16::from_be_bytes([value[4], value[5]]),
            flags_fragment_offset: u16::from_be_bytes([value[6], value[7]]),
            ttl: value[8],
            protocol: value[9],
            header_checksum: u16::from_be_bytes([value[10], value[11]]),
            src: Ipv4Address(u32::from_be_bytes([
                value[12], value[13], value[14], value[15],
            ])),
            dst: Ipv4Address(u32::from_be_bytes([
                value[16], value[17], value[18], value[19],
            ])),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4Interface {
    pub family: NetInterfaceFamily,
    pub unicast: Ipv4Address,
    pub netmask: Ipv4Address,
    pub broadcast: Ipv4Address,
}

impl Ipv4Interface {
    pub fn new(unicast: Ipv4Address, netmask: Ipv4Address) -> Self {
        let broadcast = Ipv4Address(unicast.0 & 0xffffff00 | !netmask.0 & 0xff);
        Ipv4Interface {
            family: NetInterfaceFamily::Ipv4,
            unicast,
            netmask,
            broadcast,
        }
    }
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
