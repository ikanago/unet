use std::sync::Arc;

use log::debug;

use crate::protocols::{
    self,
    ipv4::{Ipv4Address, Ipv4Interface},
    NetProtocolContext,
};
use crate::transport::TransportProtocolNumber;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply = 0,
    Echo = 8,
}

impl TryFrom<u8> for IcmpType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IcmpType::EchoReply),
            8 => Ok(IcmpType::Echo),
            _ => Err(anyhow::anyhow!("unknown icmp type: {}", value)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IcmpHeader {
    pub ty: IcmpType,
    pub code: u8,
    pub checksum: u16,
    pub values: u32,
}

impl IcmpHeader {
    fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.ty as u8,
            self.code,
            self.checksum.to_be_bytes()[0],
            self.checksum.to_be_bytes()[1],
            self.values.to_be_bytes()[0],
            self.values.to_be_bytes()[1],
            self.values.to_be_bytes()[2],
            self.values.to_be_bytes()[3],
        ]
    }
}

impl TryFrom<&[u8]> for IcmpHeader {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let ty = IcmpType::try_from(data[0])?;
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let values = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        Ok(IcmpHeader {
            ty,
            code,
            checksum,
            values,
        })
    }
}

#[tracing::instrument(skip(context, code, values, data))]
pub fn send(
    context: &mut NetProtocolContext,
    ty: IcmpType,
    code: u8,
    values: u32,
    data: &[u8],
    src: Ipv4Address,
    dst: Ipv4Address,
) -> anyhow::Result<()> {
    let header = IcmpHeader {
        ty,
        code,
        checksum: 0,
        values,
    };
    let mut buffer = header.to_bytes();
    buffer.extend_from_slice(data);
    let checksum = crate::utils::calculate_checksum(&buffer, 0);
    buffer[2] = checksum.to_be_bytes()[0];
    buffer[3] = checksum.to_be_bytes()[1];
    debug!(
        "icmp packet transmitted, ty: {:?}, src: {}, dst: {}",
        header.ty,
        src.to_string(),
        dst.to_string(),
    );

    protocols::ipv4::send(context, TransportProtocolNumber::Icmp, &buffer, src, dst)
}

#[tracing::instrument(skip(context, data))]
pub fn recv(
    context: &mut NetProtocolContext,
    data: &[u8],
    src: Ipv4Address,
    dst: Ipv4Address,
) -> anyhow::Result<()> {
    let header = IcmpHeader::try_from(data)?;
    debug!(
        "icmp packet received, ty: {:?}, src: {}, dst: {}",
        header.ty,
        src.to_string(),
        dst.to_string(),
    );
    if header.ty == IcmpType::Echo {
        send(
            context,
            IcmpType::EchoReply,
            header.code,
            header.values,
            &data[8..],
            dst,
            src,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_icmp_header() {
        let data = [
            0x08, 0x00, 0x35, 0x64, 0x00, 0x80, 0x00, 0x01, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x37, 0x38, 0x39, 0x30, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29,
        ];
        let header = IcmpHeader::try_from(data.as_ref()).unwrap();
        assert_eq!(header.ty, IcmpType::Echo);
        assert_eq!(header.code, 0x00);
        assert_eq!(header.checksum, 0x3564);
        assert_eq!(header.values, 0x00800001);
    }
}
