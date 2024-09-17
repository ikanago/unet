use udp::UdpContext;

use crate::protocols::ipv4::Ipv4Address;

pub mod icmp;
pub mod udp;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProtocolNumber {
    Icmp = 1,
    Udp = 17,
}

impl TryFrom<u8> for TransportProtocolNumber {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TransportProtocolNumber::Icmp),
            17 => Ok(TransportProtocolNumber::Udp),
            _ => Err(anyhow::anyhow!(
                "unknown transport protocol number: {}",
                value
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub address: Ipv4Address,
    pub port: u16,
}

impl Endpoint {
    pub fn new(address: &[u8], port: u16) -> Self {
        Self {
            address: Ipv4Address::new(address),
            port,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

pub struct ContextBlocks {
    pub udp_pcb: UdpContext,
}

impl ContextBlocks {
    pub fn new() -> Self {
        ContextBlocks {
            udp_pcb: UdpContext::new(),
        }
    }
}
