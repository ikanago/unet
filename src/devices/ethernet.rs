use crate::{
    driver::{tap, DriverType},
    protocols::NetProtocolType,
};

use super::NetDevice;

pub const MAC_ADDRESS_LEN: usize = 6;
pub const ETHERNET_FRAME_MIN_SIZE: usize = 60; // w/o FCS
pub const ETHERNET_FRAME_MAX_SIZE: usize = 1514; // w/o FCS
pub const ETHERNET_HEADER_SIZE: usize = 14;
pub const ETHERNET_PAYLOAD_MIN_SIZE: usize = ETHERNET_FRAME_MIN_SIZE - ETHERNET_HEADER_SIZE;
pub const ETHERNET_PAYLOAD_MAX_SIZE: usize = ETHERNET_FRAME_MAX_SIZE - ETHERNET_HEADER_SIZE;

pub const MAC_ADDRESS_ANY: MacAddress = MacAddress([0x00; MAC_ADDRESS_LEN]);
pub const MAC_ADDRESS_BROADCAST: MacAddress = MacAddress([0xff; MAC_ADDRESS_LEN]);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; MAC_ADDRESS_LEN]);

impl From<&[u8]> for MacAddress {
    fn from(data: &[u8]) -> Self {
        let mut addr = [0; MAC_ADDRESS_LEN];
        addr.copy_from_slice(&data[..MAC_ADDRESS_LEN]);
        MacAddress(addr)
    }
}

#[derive(Clone, Debug)]
pub struct EthernetHeader {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ty: NetProtocolType,
}

impl EthernetHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(14);
        bytes.extend_from_slice(&self.dst.0);
        bytes.extend_from_slice(&self.src.0);
        bytes.extend_from_slice(&(self.ty as u16).to_be_bytes());
        bytes
    }
}

impl TryFrom<&[u8]> for EthernetHeader {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let dst = MacAddress::from(&value[0..MAC_ADDRESS_LEN]);
        let src = MacAddress::from(&value[MAC_ADDRESS_LEN..2 * MAC_ADDRESS_LEN]);
        let ty = NetProtocolType::try_from(u16::from_be_bytes([value[12], value[13]]))?;
        Ok(EthernetHeader { dst, src, ty })
    }
}

#[tracing::instrument(skip_all)]
pub fn recv(device: &mut NetDevice) -> anyhow::Result<(NetProtocolType, Vec<u8>)> {
    let data = match device.driver.as_ref().expect("device driver not set") {
        DriverType::Tap { .. } => tap::read(device)?,
    };
    let header = EthernetHeader::try_from(data.as_ref())?;
    if header.dst != MacAddress::from(&device.hw_addr[..MAC_ADDRESS_LEN])
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
    // debug!(
    //     "ethernet frame received, dev: {}, ty: {:?}, data: {:?}",
    //     device.name, ty, data
    // );
    Ok((ty, payload))
}
