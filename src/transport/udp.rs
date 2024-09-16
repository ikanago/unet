use log::debug;

use crate::{
    protocols::{
        ipv4::{self, Ipv4Address, IPV4_PAYLOAD_MAX_LENGTH},
        NetProtocolContext,
    },
    utils::{calculate_checksum, to_bytes, to_bytes_mut, to_struct},
};

use super::{Endpoint, TransportProtocolNumber};

#[derive(Debug, Clone)]
struct PseudoHeader {
    src: Ipv4Address,
    dst: Ipv4Address,
    zero: u8,
    protocol: TransportProtocolNumber,
    length: u16,
}

#[repr(packed)]
#[derive(Debug, Clone)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

#[tracing::instrument(skip_all)]
pub fn send(
    context: &mut NetProtocolContext,
    data: &[u8],
    src: Endpoint,
    dst: Endpoint,
) -> anyhow::Result<()> {
    if data.len() > IPV4_PAYLOAD_MAX_LENGTH - size_of::<UdpHeader>() {
        anyhow::bail!(
            "udp packet too long, len: {}, max: {}",
            data.len(),
            IPV4_PAYLOAD_MAX_LENGTH - size_of::<UdpHeader>()
        );
    }
    let length = (size_of::<UdpHeader>() + data.len()) as u16;
    debug!(
        "send udp packet, src: {:?}, dst: {:?}, length: {}",
        src, dst, length
    );
    let pseudo_header = PseudoHeader {
        src: src.address,
        dst: dst.address,
        zero: 0,
        protocol: TransportProtocolNumber::Udp,
        length,
    };
    let mut header = UdpHeader {
        src_port: src.port.to_be(),
        dst_port: dst.port.to_be(),
        length: length.to_be(),
        checksum: 0,
    };
    let header_bytes = unsafe { to_bytes_mut(&mut header) };
    let sum = calculate_checksum(unsafe { to_bytes(&pseudo_header) }, 0);
    let mut data = [header_bytes.to_vec(), data.to_vec()].concat();
    let sum = calculate_checksum(&data, !sum);
    data[6..8].copy_from_slice(&sum.to_be_bytes());

    debug!(
        "udp packet sent: src: {}, dst: {}, len: {}",
        src, dst, length
    );
    ipv4::send(
        context,
        TransportProtocolNumber::Udp,
        &data,
        src.address,
        dst.address,
    )
}

#[tracing::instrument(skip_all)]
pub fn recv(data: &[u8], src: Ipv4Address, dst: Ipv4Address) -> anyhow::Result<()> {
    let header_len = size_of::<UdpHeader>();
    if data.len() < header_len {
        anyhow::bail!("udp packet too short, len: {}", data.len());
    }
    let sum = calculate_checksum(data, 0);
    let (header, payload) = data.split_at(header_len);
    let header = unsafe { to_struct::<UdpHeader>(header) };
    if data.len() != header.length.to_be() as usize {
        anyhow::bail!(
            "invalid udp packet length, len: {}, header.length: {:?}",
            data.len(),
            header.length.to_be()
        );
    }

    let pseudo_header = PseudoHeader {
        src,
        dst,
        zero: 0,
        protocol: TransportProtocolNumber::Udp,
        length: header.length.to_be(),
    };
    let sum = calculate_checksum(unsafe { to_bytes(&pseudo_header) }, !sum);
    if sum != 0 {
        anyhow::bail!(
            "invalid udp checksum: 0x{:04x}, 0x{:04x}",
            sum,
            header.checksum.to_be()
        );
    }

    debug!(
        "udp packet received, src: {:?}, dst: {:?}, len: {}",
        header.src_port.to_be(),
        header.dst_port.to_be(),
        header.length.to_be()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_udp_header() {
        let data = [
            0x12, 0x34, 0x56, 0x78, 0x00, 0x0c, 0x93, 0x41, 0x01, 0x02, 0x03, 0x04,
        ];
        let (header, payload) = data.split_at(size_of::<UdpHeader>());
        let header = unsafe { to_struct::<UdpHeader>(&header) };
        assert_eq!(header.src_port.to_be(), 0x1234);
        assert_eq!(header.dst_port.to_be(), 0x5678);
        assert_eq!(header.length.to_be(), 0xc);
        assert_eq!(header.checksum.to_be(), 0x9341);
        assert_eq!(payload, [0x01, 0x02, 0x03, 0x04]);
    }
}
