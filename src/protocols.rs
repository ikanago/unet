use std::{
    collections::{LinkedList, VecDeque},
    sync::{Arc, Mutex},
};

use ipv4::{IpRouter, Ipv4IdGenerator, Ipv4QueueEntry};
use log::debug;

pub mod ipv4;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetProtocolType {
    Ipv4 = 0x0800,
}

impl NetProtocolType {
    pub fn to_family(&self) -> NetInterfaceFamily {
        match self {
            NetProtocolType::Ipv4 => NetInterfaceFamily::Ipv4,
        }
    }
}

impl TryFrom<u16> for NetProtocolType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0800 => Ok(NetProtocolType::Ipv4),
            _ => Err(anyhow::anyhow!(
                "unknown network protocol type: 0x{:04x}",
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

pub struct NetProtocol {
    pub protocol_type: NetProtocolType,
    // TODO: can I remove queue and call handle_isr directly?
    pub queue: Arc<Mutex<VecDeque<Ipv4QueueEntry>>>,
}

impl NetProtocol {
    pub fn recv(&self, context: &mut NetProtocolContext) -> anyhow::Result<()> {
        let mut queue = self.queue.lock().unwrap();
        while let Some(entry) = queue.pop_front() {
            debug!("ipv4 protocol queue popped, len: {}", queue.len());
            debug!("ipv4 protocol queue entry: {:?}", entry);
            ipv4::handle_input(entry.interface, context, &entry.data)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NetProtocolContext {
    pub router: IpRouter,
    pub id_manager: Ipv4IdGenerator,
}

impl NetProtocolContext {
    pub fn new() -> Self {
        NetProtocolContext {
            router: IpRouter::new(),
            id_manager: Ipv4IdGenerator::new(),
        }
    }
}
