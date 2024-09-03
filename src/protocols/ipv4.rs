use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use super::{NetProtocol, ProtocolType};

#[derive(Clone, Debug)]
pub struct Ipv4QueueEntry {
    pub data: Vec<u8>,
}

impl NetProtocol {
    pub fn ipv4() -> Self {
        NetProtocol {
            protocol_type: ProtocolType::Ipv4,
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}
