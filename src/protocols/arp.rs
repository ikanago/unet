use std::{collections::HashMap, time::Duration};

use log::debug;

use crate::{
    devices::{
        ethernet::{MacAddress, MAC_ADDRESS_BROADCAST, MAC_ADDRESS_LEN},
        NetDevice, NetDeviceType,
    },
    protocols::{
        ipv4::{Ipv4Address, Ipv4Interface},
        NetProtocolType,
    },
};

use super::NetProtocolContext;

const ARP_HARDWARE_TYPE_ETHERNET: u16 = 1;
const ARP_OPERATION_REQUEST: u16 = 1;
const ARP_OPERATION_REPLY: u16 = 2;
const ARP_CACHE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Debug)]
pub struct ArpHeader {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: u16,
}

impl From<&[u8]> for ArpHeader {
    fn from(data: &[u8]) -> Self {
        let htype = u16::from_be_bytes([data[0], data[1]]);
        let ptype = u16::from_be_bytes([data[2], data[3]]);
        let hlen = data[4];
        let plen = data[5];
        let oper = u16::from_be_bytes([data[6], data[7]]);
        ArpHeader {
            htype,
            ptype,
            hlen,
            plen,
            oper,
        }
    }
}

impl ArpHeader {
    fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.htype.to_be_bytes()[0],
            self.htype.to_be_bytes()[1],
            self.ptype.to_be_bytes()[0],
            self.ptype.to_be_bytes()[1],
            self.hlen,
            self.plen,
            self.oper.to_be_bytes()[0],
            self.oper.to_be_bytes()[1],
        ]
    }
}

#[derive(Clone, Debug)]
pub struct ArpMessage {
    pub header: ArpHeader,
    pub sha: MacAddress,
    pub spa: Ipv4Address,
    pub tha: MacAddress,
    pub tpa: Ipv4Address,
}

impl From<&[u8]> for ArpMessage {
    fn from(data: &[u8]) -> Self {
        let header = ArpHeader::from(&data[0..8]);
        let sha = MacAddress::from(&data[8..14]);
        let spa = Ipv4Address(u32::from_be_bytes(data[14..18].try_into().unwrap()));
        let tha = MacAddress::from(&data[18..24]);
        let tpa = Ipv4Address(u32::from_be_bytes(data[24..28].try_into().unwrap()));
        ArpMessage {
            header,
            sha,
            spa,
            tha,
            tpa,
        }
    }
}

impl ArpMessage {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.sha.0);
        bytes.extend_from_slice(&self.spa.0.to_be_bytes());
        bytes.extend_from_slice(&self.tha.0);
        bytes.extend_from_slice(&self.tpa.0.to_be_bytes());
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ArpCacheState {
    Incomplete,
    Resolved(MacAddress),
}

#[derive(Clone, Debug, Hash)]
struct ArpCacheEntry {
    state: ArpCacheState,
    timestamp: std::time::Instant,
}

#[derive(Clone, Debug)]
pub struct ArpCache {
    entries: HashMap<Ipv4Address, ArpCacheEntry>,
}

impl ArpCache {
    pub fn new() -> Self {
        ArpCache {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, ip_addr: Ipv4Address, state: ArpCacheState) {
        let entry = ArpCacheEntry {
            state,
            timestamp: std::time::Instant::now(),
        };
        self.entries.insert(ip_addr, entry);
    }

    pub fn get(&self, ip_addr: &Ipv4Address) -> Option<ArpCacheState> {
        if let Some(entry) = self.entries.get(ip_addr) {
            if let ArpCacheState::Resolved(_) = &entry.state {
                if entry.timestamp.elapsed() < ARP_CACHE_TIMEOUT {
                    return Some(entry.state.clone());
                }
            }
        }
        None
    }
}

#[tracing::instrument(skip(device, interface))]
fn request(
    device: &mut NetDevice,
    interface: &Ipv4Interface,
    target: Ipv4Address,
) -> anyhow::Result<()> {
    send(
        device,
        interface,
        ARP_OPERATION_REQUEST,
        MAC_ADDRESS_BROADCAST,
        target,
    )
}

#[tracing::instrument(skip(device, interface))]
fn reply(
    device: &mut NetDevice,
    interface: &Ipv4Interface,
    target_hw_addr: MacAddress,
    target: Ipv4Address,
) -> anyhow::Result<()> {
    send(
        device,
        interface,
        ARP_OPERATION_REPLY,
        target_hw_addr,
        target,
    )
}

fn send(
    device: &mut NetDevice,
    interface: &Ipv4Interface,
    oper: u16,
    target_hw_addr: MacAddress,
    target: Ipv4Address,
) -> anyhow::Result<()> {
    let header = ArpHeader {
        htype: ARP_HARDWARE_TYPE_ETHERNET,
        ptype: NetProtocolType::Ipv4 as u16,
        hlen: MAC_ADDRESS_LEN as u8,
        plen: 4,
        oper,
    };
    let messeage = ArpMessage {
        header,
        sha: device.hw_addr[0..MAC_ADDRESS_LEN].try_into().unwrap(),
        spa: interface.unicast,
        tha: target_hw_addr.clone(),
        tpa: target,
    };
    debug!("arp send: {:?}", messeage,);

    let data = messeage.to_bytes();
    device.send(&data, NetProtocolType::Arp, target_hw_addr)?;
    Ok(())
}

#[tracing::instrument(skip_all)]
pub fn recv(
    context: &mut NetProtocolContext,
    interface: &Ipv4Interface,
    data: &[u8],
) -> anyhow::Result<()> {
    let header = ArpHeader::from(&data[0..8]);
    if header.htype != ARP_HARDWARE_TYPE_ETHERNET {
        anyhow::bail!("unknown hardware type: {}", header.htype);
    }
    if header.ptype != NetProtocolType::Ipv4 as u16 {
        anyhow::bail!("unknown protocol type: {}", header.ptype);
    }
    if header.hlen != MAC_ADDRESS_LEN as u8 {
        anyhow::bail!("unknown hardware address length: {}", header.hlen);
    }
    if header.plen != 4 {
        anyhow::bail!("unknown protocol address length: {}", header.plen);
    }

    let arp = ArpMessage::from(data);
    debug!(
        "arp recv: {:?}, interface: {}",
        arp,
        interface.unicast.to_string()
    );

    let Some(device) = interface.device.as_ref() else {
        anyhow::bail!(
            "device not found, interface: {}",
            interface.unicast.to_string()
        );
    };
    if interface.unicast == arp.tpa {
        context
            .arp_cache
            .insert(arp.spa, ArpCacheState::Resolved(arp.sha.clone()));
        let device = device.upgrade().unwrap();
        let mut device = device.lock().unwrap();
        reply(&mut device, &interface, arp.sha, arp.spa)?;
    }
    Ok(())
}

#[tracing::instrument(skip(device, interface, arp_cache))]
pub fn resolve_arp(
    device: &mut NetDevice,
    interface: &Ipv4Interface,
    arp_cache: &mut ArpCache,
    target: Ipv4Address,
) -> anyhow::Result<ArpCacheState> {
    if device.ty != NetDeviceType::Ethernet {
        anyhow::bail!("device type not supported: {:?}", device.ty);
    }

    let Some(state) = arp_cache.get(&target) else {
        arp_cache.insert(target, ArpCacheState::Incomplete);
        request(device, interface, target)?;
        return Ok(ArpCacheState::Incomplete);
    };
    if state == ArpCacheState::Incomplete {
        request(device, interface, target)?;
    }
    Ok(state)
}
