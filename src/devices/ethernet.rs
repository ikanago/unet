use log::debug;

use crate::{
    driver::{tap, DriverType},
    protocols::NetProtocolType,
};

use super::NetDevice;

pub const MAC_ADDRESS_SIZE: usize = 6;
const ETHERNET_MIN_SIZE: usize = 60; // w/o FCS
const ETHERNET_HEADER_SIZE: usize = 14;

pub const MAC_ADDRESS_ANY: MacAddress = MacAddress([0x00; MAC_ADDRESS_SIZE]);
pub const MAC_ADDRESS_BROADCAST: MacAddress = MacAddress([0xff; MAC_ADDRESS_SIZE]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacAddress(pub [u8; MAC_ADDRESS_SIZE]);

impl From<&[u8]> for MacAddress {
    fn from(data: &[u8]) -> Self {
        let mut addr = [0; MAC_ADDRESS_SIZE];
        addr.copy_from_slice(&data[..MAC_ADDRESS_SIZE]);
        MacAddress(addr)
    }
}

#[derive(Clone, Debug)]
pub struct EthernetHeader {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ty: u16,
}

impl EthernetHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(14);
        bytes.extend_from_slice(&self.dst.0);
        bytes.extend_from_slice(&self.src.0);
        bytes.extend_from_slice(&self.ty.to_be_bytes());
        bytes
    }
}

impl From<&[u8]> for EthernetHeader {
    fn from(value: &[u8]) -> Self {
        let dst = MacAddress::from(&value[0..MAC_ADDRESS_SIZE]);
        let src = MacAddress::from(&value[MAC_ADDRESS_SIZE..2 * MAC_ADDRESS_SIZE]);
        let ethertype = u16::from_be_bytes([value[12], value[13]]);
        EthernetHeader {
            dst,
            src,
            ty: ethertype,
        }
    }
}

pub fn send(device: &NetDevice, ty: u16, data: &[u8], dst: MacAddress) -> anyhow::Result<()> {
    let header = EthernetHeader {
        dst,
        src: MacAddress::from(device.hw_addr[..MAC_ADDRESS_SIZE].as_ref()),
        ty,
    };

    let mut frame = header.to_bytes();
    frame.extend_from_slice(data);

    let len_padding = if data.len() < ETHERNET_MIN_SIZE {
        ETHERNET_MIN_SIZE - data.len()
    } else {
        0
    };
    frame.extend_from_slice(&vec![0; len_padding]);

    debug!(
        "ethernet frame transmitted, dev: {}, type: 0x{:#04x}, len: {}",
        device.name,
        ty,
        frame.len()
    );

    Ok(())
}

pub fn recv(device: &NetDevice) -> anyhow::Result<(NetProtocolType, Vec<u8>)> {
    let data = match device.driver.as_ref().expect("device driver not set") {
        DriverType::Tap { .. } => tap::read(device)?,
    };
    let header = EthernetHeader::from(data.as_ref());
    if header.dst != MacAddress::from(&device.hw_addr[..MAC_ADDRESS_SIZE])
        && header.dst != MAC_ADDRESS_BROADCAST
    {
        anyhow::bail!(
            "ethernet frame not for me, dev: {}, dst: {:?}",
            device.name,
            header.dst
        );
    }

    let ty = NetProtocolType::try_from(header.ty)?;
    let payload = data[ETHERNET_HEADER_SIZE..].to_vec();
    Ok((ty, payload))
}
