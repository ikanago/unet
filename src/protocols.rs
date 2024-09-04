use std::{
    borrow::Borrow,
    collections::{LinkedList, VecDeque},
    sync::{Arc, Mutex},
};

use ipv4::{
    IpRouter, Ipv4Address, Ipv4Header, Ipv4IdGenerator, Ipv4Interface, Ipv4QueueEntry,
    IPV4_ADDR_ANY, IPV4_ADDR_BROADCAST,
};
use log::{debug, error};

use crate::devices::NetDevice;

pub mod ipv4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolType {
    Ipv4 = 0x0800,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetInterfaceFamily {
    Ipv4 = 1,
}

pub type NetProtocols = LinkedList<NetProtocol>;

pub struct NetProtocol {
    pub protocol_type: ProtocolType,
    pub queue: Arc<Mutex<VecDeque<Ipv4QueueEntry>>>,
}

impl NetProtocol {
    pub fn handle_isr(&self, context: &mut NetProtocolContext) -> anyhow::Result<()> {
        let mut queue = self.queue.lock().unwrap();
        while let Some(entry) = queue.pop_front() {
            debug!("ipv4 protocol queue popped, len: {}", queue.len());
            debug!("ipv4 protocol queue entry: {:?}", entry);
            self.handle_ipv4_input(&entry.device, context, &entry.data)?;
        }
        Ok(())
    }

    pub fn handle_ipv4_input(
        &self,
        device: &NetDevice,
        context: &mut NetProtocolContext,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let header = Ipv4Header::try_from(data.as_ref())?;
        header.validate()?;
        let Some(interface) = device.get_interface(NetInterfaceFamily::Ipv4) else {
            debug!("no ipv4 interface, dev: {}", device.name);
            return Ok(());
        };
        if header.dst != interface.unicast
            && header.dst != interface.broadcast
            && header.dst != IPV4_ADDR_BROADCAST
        {
            return Ok(());
        }
        debug!(
            "ipv4 packet received, dev: {}, src:{}, dst: {}, interface: {:?}",
            device.name,
            header.src.to_string(),
            header.dst.to_string(),
            interface
        );
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
