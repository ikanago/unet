use std::collections::VecDeque;

use log::{debug, error};

use crate::{
    protocols::{
        ipv4::{self, Ipv4Address, IPV4_PAYLOAD_MAX_LENGTH},
        ProtocolStackContext,
    },
    utils::calculate_checksum,
};

use super::{ContextBlocks, Endpoint, TransportProtocolNumber};

const UDP_PCB_LENGTH: usize = 16;

#[derive(Debug, Clone)]
struct PseudoHeader {
    src: Ipv4Address,
    dst: Ipv4Address,
    zero: u8,
    protocol: TransportProtocolNumber,
    length: u16,
}

impl PseudoHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.src.to_bytes());
        bytes.extend_from_slice(&self.dst.to_bytes());
        bytes.push(self.zero);
        bytes.push(self.protocol as u8);
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

impl UdpHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.src_port.to_be_bytes());
        bytes.extend_from_slice(&self.dst_port.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes
    }
}

impl From<&[u8]> for UdpHeader {
    fn from(data: &[u8]) -> Self {
        Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PcbState {
    Open = 0,
    Closing = 1,
}

#[derive(Debug, Clone)]
struct UdpPcb {
    state: PcbState,
    local: Endpoint,
    queue: VecDeque<UdpPcbQueueEntry>,
}

impl UdpPcb {
    const DEFAULT: Option<Self> = None;

    fn can_be_bound(&self, address: Ipv4Address, port: u16) -> bool {
        self.state == PcbState::Open
            && (self.local.address == Ipv4Address::ANY
                || address == Ipv4Address::ANY
                || self.local.address == address)
            && self.local.port == port
    }
}

#[derive(Debug, Clone)]
struct UdpPcbQueueEntry {
    foreign: Endpoint,
    data: Vec<u8>,
}

pub struct UdpContext {
    pcbs: [Option<UdpPcb>; UDP_PCB_LENGTH],
}

impl UdpContext {
    pub fn new() -> Self {
        Self {
            pcbs: [UdpPcb::DEFAULT; UDP_PCB_LENGTH],
        }
    }

    pub fn select_pcb(&self, address: Ipv4Address, port: u16) -> Option<&UdpPcb> {
        for pcb in self
            .pcbs
            .iter()
            .filter(|pcb| pcb.is_some())
            .map(|pcb| pcb.as_ref().unwrap())
        {
            if pcb.can_be_bound(address, port) {
                return Some(pcb);
            }
        }
        None
    }

    pub fn select_pcb_mut(&mut self, address: Ipv4Address, port: u16) -> Option<&mut UdpPcb> {
        for pcb in self
            .pcbs
            .iter_mut()
            .filter(|pcb| pcb.is_some())
            .map(|pcb| pcb.as_mut().unwrap())
        {
            if pcb.can_be_bound(address, port) {
                return Some(pcb);
            }
        }
        None
    }
}

pub fn bind(pcbs: &mut ContextBlocks, endpoint: &Endpoint) -> Option<usize> {
    if pcbs
        .udp_pcb
        .select_pcb(endpoint.address, endpoint.port)
        .is_some()
    {
        error!("udp socket already bound, endpoint: {}", endpoint);
        return None;
    }

    for (i, pcb) in pcbs
        .udp_pcb
        .pcbs
        .iter_mut()
        .enumerate()
        .filter(|(_, pcb)| pcb.is_none())
    {
        *pcb = Some(UdpPcb {
            state: PcbState::Open,
            local: endpoint.clone(),
            queue: VecDeque::new(),
        });
        debug!("bound udp socket, i: {}, pcb: {}", i, endpoint);
        return Some(i);
    }
    None
}

#[tracing::instrument(skip_all)]
pub fn send(
    context: &mut ProtocolStackContext,
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
    let header = UdpHeader {
        src_port: src.port,
        dst_port: dst.port,
        length: length,
        checksum: 0,
    };
    let header_bytes = header.to_bytes();
    let sum = calculate_checksum(&pseudo_header.to_bytes(), 0);
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

#[tracing::instrument(skip(pcbs, data))]
pub fn recv(
    pcbs: &mut ContextBlocks,
    data: &[u8],
    src: Ipv4Address,
    dst: Ipv4Address,
) -> anyhow::Result<()> {
    let header_len = size_of::<UdpHeader>();
    if data.len() < header_len {
        anyhow::bail!("udp packet too short, len: {}", data.len());
    }
    let sum = calculate_checksum(data, 0);
    let (header, payload) = data.split_at(header_len);
    let header = UdpHeader::from(header);
    if data.len() != header.length as usize {
        anyhow::bail!(
            "invalid udp packet length, len: {}, header.length: {:?}",
            data.len(),
            header.length
        );
    }

    let pseudo_header = PseudoHeader {
        src,
        dst,
        zero: 0,
        protocol: TransportProtocolNumber::Udp,
        length: header.length,
    };
    let sum = calculate_checksum(&pseudo_header.to_bytes(), !sum);
    if sum != 0 {
        anyhow::bail!(
            "invalid udp checksum: 0x{:04x}, 0x{:04x}",
            sum,
            header.checksum
        );
    }

    debug!(
        "udp packet received, src: {:?}, dst: {:?}, payload len: {}",
        header.src_port,
        header.dst_port,
        payload.len()
    );

    let Some(pcb) = pcbs.udp_pcb.select_pcb_mut(dst, header.dst_port) else {
        anyhow::bail!(
            "udp socket not found, dst: {}, port: {}",
            dst,
            header.dst_port
        );
    };
    pcb.queue.push_back(UdpPcbQueueEntry {
        foreign: Endpoint {
            address: dst,
            port: header.src_port,
        },
        data: payload.to_vec(),
    });
    debug!("udp queue pushed, len: {}", pcb.queue.len());
    Ok(())
}
