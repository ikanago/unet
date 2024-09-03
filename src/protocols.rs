use std::{
    collections::{LinkedList, VecDeque},
    sync::{Arc, Mutex},
};

use ipv4::{Ipv4Header, Ipv4QueueEntry};
use log::debug;

pub mod ipv4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolType {
    Ipv4 = 0x0800,
    Unknown,
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
            // std::thread::sleep(std::time::Duration::from_millis(500));
            let header = Ipv4Header::try_from(entry.data.as_ref())?;
            header.validate()?;
        }
        Ok(())
    }
}
