use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use log::debug;
use signal_hook::low_level::raise;

use crate::{
    interrupt::{IrqEntry, INTR_IRQ_LOOPBACK},
    protocols::NetProtocolType,
};

use super::{NetDevice, NetDeviceQueueEntry, NET_DEVICE_FLAG_LOOPBACK};

pub const LOOPBACK_MTU: usize = u16::MAX as usize;

#[derive(Clone, Debug)]
pub struct LoopbackQueueEntry {
    pub data: Vec<u8>,
}

fn open(_: &mut NetDevice) -> anyhow::Result<()> {
    Ok(())
}

fn close(_: &mut NetDevice) -> anyhow::Result<()> {
    Ok(())
}

#[tracing::instrument(skip_all)]
fn send(
    dev: &mut NetDevice,
    data: &[u8],
    _ty: NetProtocolType,
    _dst: [u8; super::NET_DEVICE_ADDR_LEN],
) -> anyhow::Result<()> {
    let entry = LoopbackQueueEntry {
        data: data.to_vec(),
    };
    let NetDeviceQueueEntry::Loopback(ref queue) = dev.queue else {
        anyhow::bail!("invalid queue type, expected loopback");
    };
    let mut queue = queue.lock().unwrap();
    queue.push_back(entry);
    debug!(
        "net device queue pushed, dev: {}, len: {}",
        dev.name,
        queue.len()
    );

    raise(INTR_IRQ_LOOPBACK)?;
    Ok(())
}

#[tracing::instrument(skip_all)]
pub fn recv(dev: &NetDevice) -> anyhow::Result<(NetProtocolType, Vec<u8>)> {
    let NetDeviceQueueEntry::Loopback(ref queue) = dev.queue else {
        anyhow::bail!("invalid queue type, expected loopback");
    };
    let mut queue = queue.lock().unwrap();
    let entry = queue
        .pop_front()
        .ok_or(anyhow::anyhow!("loopback queue is empty"))?
        .data;
    debug!(
        "net device queue popped, dev: {}, len: {}",
        dev.name,
        queue.len()
    );
    Ok((NetProtocolType::Ipv4, entry))
}

impl NetDevice {
    pub fn loopback() -> Self {
        let irq_entry = IrqEntry {
            irq: INTR_IRQ_LOOPBACK,
            flags: 0x00,
        };

        Self {
            index: 0,
            name: "lo".to_string(),
            ty: super::NetDeviceType::Loopback,
            mtu: LOOPBACK_MTU,
            flags: NET_DEVICE_FLAG_LOOPBACK,
            header_len: 0,
            addr_len: 0,
            hw_addr: [0; super::NET_DEVICE_ADDR_LEN],
            cast_type: super::CastType::Peer([0; super::NET_DEVICE_ADDR_LEN]),
            ops: super::NetDeviceOps {
                open: open,
                close: close,
                transmit: send,
            },
            driver: None,
            irq_entry,
            queue: NetDeviceQueueEntry::Loopback(Arc::new(Mutex::new(VecDeque::new()))),
            interfaces: Default::default(),
        }
    }
}
