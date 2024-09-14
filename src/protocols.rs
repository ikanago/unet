use std::{
    collections::{LinkedList, VecDeque},
    sync::{Arc, Mutex},
};

use arp::ArpCache;
use ipv4::{IpRouter, Ipv4IdGenerator, Ipv4Interface};
use log::debug;

pub mod arp;
pub mod ipv4;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetProtocolType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
}

impl NetProtocolType {
    pub fn to_family(&self) -> NetInterfaceFamily {
        match self {
            NetProtocolType::Ipv4 | NetProtocolType::Arp => NetInterfaceFamily::Ipv4,
        }
    }
}

impl TryFrom<u16> for NetProtocolType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0800 => Ok(NetProtocolType::Ipv4),
            0x0806 => Ok(NetProtocolType::Arp),
            _ => Err(anyhow::anyhow!(
                "unknown network protocol type: {:04x}",
                value
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetInterfaceFamily {
    Ipv4 = 1,
}

pub type NetProtocols = LinkedList<NetProtocol>;

#[derive(Clone, Debug)]
pub struct Ipv4QueueEntry {
    pub data: Vec<u8>,
    // pub device: Arc<NetDevice>,
    pub interface: Arc<Ipv4Interface>,
}

pub struct NetProtocol {
    pub protocol_type: NetProtocolType,
    // TODO: can I remove queue and call handle_isr directly?
    pub queue: Arc<Mutex<VecDeque<Ipv4QueueEntry>>>,
}

impl NetProtocol {
    pub fn ipv4() -> Self {
        NetProtocol {
            protocol_type: NetProtocolType::Ipv4,
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn arp() -> Self {
        NetProtocol {
            protocol_type: NetProtocolType::Arp,
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

impl NetProtocol {
    #[tracing::instrument(skip_all)]
    pub fn recv(&self, context: &mut NetProtocolContext) -> anyhow::Result<()> {
        let mut queue = self.queue.lock().unwrap();
        while let Some(entry) = queue.pop_front() {
            debug!("net protocol queue popped, len: {}", queue.len());
            match self.protocol_type {
                NetProtocolType::Ipv4 => ipv4::recv(entry.interface, context, &entry.data)?,
                NetProtocolType::Arp => arp::recv(&entry.interface, context, &entry.data)?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NetProtocolContext {
    pub arp_cache: ArpCache,
    pub router: IpRouter,
    pub id_manager: Ipv4IdGenerator,
}

impl NetProtocolContext {
    pub fn new() -> Self {
        NetProtocolContext {
            arp_cache: ArpCache::new(),
            router: IpRouter::new(),
            id_manager: Ipv4IdGenerator::new(),
        }
    }
}
