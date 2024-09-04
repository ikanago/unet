use std::{
    collections::{LinkedList, VecDeque},
    sync::{Arc, Mutex},
};

use ipv4::{Ipv4Header, Ipv4QueueEntry, IPV4_ADDR_BROADCAST};
use log::debug;

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
    pub fn handle_isr(&self) -> anyhow::Result<()> {
        let mut queue = self.queue.lock().unwrap();
        while let Some(entry) = queue.pop_front() {
            debug!("ipv4 protocol queue popped, len: {}", queue.len());
            debug!("ipv4 protocol queue entry: {:?}", entry);
            self.handle_ipv4_input(&entry.data, &entry.device)?;
        }
        Ok(())
    }

    pub fn handle_ipv4_input(&self, data: &[u8], device: &NetDevice) -> anyhow::Result<()> {
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
            "ipv4 packet received, dev: {}, addr:{}, interface: {:?}",
            device.name,
            header.dst.to_string(),
            interface
        );
        Ok(())
    }
}
