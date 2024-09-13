use std::sync::{Arc, Mutex};

use log::debug;

use crate::{
    devices::{ethernet::MAC_ADDRESS_SIZE, NetDevice, NET_DEVICE_ADDR_LEN},
    protocols::{
        ipv4::{Ipv4Address, Ipv4Interface},
        NetProtocolType,
    },
};

const ARP_HARDWARE_TYPE_ETHERNET: u16 = 1;
const ARP_OPERATION_REQUEST: u16 = 1;
const ARP_OPERATION_REPLY: u16 = 2;

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
    pub sha: [u8; MAC_ADDRESS_SIZE],
    pub spa: [u8; 4],
    pub tha: [u8; MAC_ADDRESS_SIZE],
    pub tpa: [u8; 4],
}

impl From<&[u8]> for ArpMessage {
    fn from(data: &[u8]) -> Self {
        let header = ArpHeader::from(&data[0..8]);
        let sha = data[8..14].try_into().unwrap();
        let spa = data[14..18].try_into().unwrap();
        let tha = data[18..24].try_into().unwrap();
        let tpa = data[24..28].try_into().unwrap();
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
        bytes.extend_from_slice(&self.sha);
        bytes.extend_from_slice(&self.spa);
        bytes.extend_from_slice(&self.tha);
        bytes.extend_from_slice(&self.tpa);
        bytes
    }
}

#[tracing::instrument(skip(device, interface))]
pub fn send(
    device: Arc<Mutex<NetDevice>>,
    interface: &Ipv4Interface,
    target_hw_addr: [u8; MAC_ADDRESS_SIZE],
    target: Ipv4Address,
) -> anyhow::Result<()> {
    let header = ArpHeader {
        htype: ARP_HARDWARE_TYPE_ETHERNET,
        ptype: NetProtocolType::Ipv4 as u16,
        hlen: MAC_ADDRESS_SIZE as u8,
        plen: 4,
        oper: ARP_OPERATION_REPLY,
    };
    let mut device = device.lock().unwrap();
    let messeage = ArpMessage {
        header,
        sha: device.hw_addr[0..MAC_ADDRESS_SIZE].try_into().unwrap(),
        spa: interface.unicast.0.to_be_bytes(),
        tha: target_hw_addr,
        tpa: target.0.to_be_bytes(),
    };
    debug!("arp send: {:?}", messeage,);

    let data = messeage.to_bytes();
    // Extend target_hw_addr to NET_DEVICE_ADDR_LEN bytes array
    let mut dst = [0; NET_DEVICE_ADDR_LEN];
    dst[..MAC_ADDRESS_SIZE].copy_from_slice(&target_hw_addr);
    device.send(&data, NetProtocolType::Arp, dst)?;
    Ok(())
}

#[tracing::instrument(skip_all)]
pub fn recv(interface: &Ipv4Interface, data: &[u8]) -> anyhow::Result<()> {
    let header = ArpHeader::from(&data[0..8]);
    if header.oper != ARP_OPERATION_REQUEST {
        anyhow::bail!("unknown operation: {}", header.oper);
    }
    if header.htype != ARP_HARDWARE_TYPE_ETHERNET {
        anyhow::bail!("unknown hardware type: {}", header.htype);
    }
    if header.ptype != NetProtocolType::Ipv4 as u16 {
        anyhow::bail!("unknown protocol type: {}", header.ptype);
    }
    if header.hlen != MAC_ADDRESS_SIZE as u8 {
        anyhow::bail!("unknown hardware address length: {}", header.hlen);
    }
    if header.plen != 4 {
        anyhow::bail!("unknown protocol address length: {}", header.plen);
    }

    let arp = ArpMessage::from(data);
    let spa = Ipv4Address(u32::from_be_bytes(arp.spa));
    let tpa = Ipv4Address(u32::from_be_bytes(arp.tpa));
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
    let device = device.upgrade().unwrap();
    if interface.unicast == tpa {
        send(device, &interface, arp.sha, spa)?;
    }
    Ok(())
}
