pub mod ethernet;
pub mod loopback;
pub mod null;

use std::{
    collections::{LinkedList, VecDeque},
    sync::{Arc, Mutex},
};

use log::{debug, info};
use signal_hook::low_level::raise;

use crate::{
    driver::DriverType,
    interrupt::{IrqEntry, INTR_IRQ_L3},
    protocols::{
        ipv4::Ipv4Interface, Ipv4QueueEntry, NetInterfaceFamily, NetProtocolType, NetProtocols,
    },
};

const NET_DEVICE_FLAG_UP: u16 = 0x0001;
pub const NET_DEVICE_FLAG_LOOPBACK: u16 = 0x0010;
const NET_DEVICE_FLAG_BROADCAST: u16 = 0x0020;
const NET_DEVICE_FLAG_P2P: u16 = 0x0040;
pub const NET_DEVICE_FLAG_NEED_ARP: u16 = 0x0100;

pub const NET_DEVICE_ADDR_LEN: usize = 14;

pub fn run_net(devices: &mut NetDevices) -> anyhow::Result<()> {
    info!("open all devices");
    for dev in devices.iter_mut() {
        let mut dev = dev.lock().unwrap();
        dev.open()?;
    }
    return Ok(());
}

pub fn stop_net(devices: &mut NetDevices) -> anyhow::Result<()> {
    info!("close all devices");
    for dev in devices.iter_mut() {
        let mut dev = dev.lock().unwrap();
        dev.close()?;
    }
    return Ok(());
}

pub fn init_net() -> anyhow::Result<()> {
    Ok(())
}

pub type NetDevices = LinkedList<Arc<Mutex<NetDevice>>>;

#[derive(Clone, Debug)]
pub enum NetDeviceQueueEntry {
    Null,
    Loopback(Arc<Mutex<VecDeque<loopback::LoopbackQueueEntry>>>),
}

#[derive(Debug, Clone)]
pub enum CastType {
    Peer([u8; NET_DEVICE_ADDR_LEN]),
    Broadcast([u8; NET_DEVICE_ADDR_LEN]),
}

#[derive(Debug, Clone)]
pub enum NetDeviceType {
    Null,
    Loopback,
    Ethernet,
}

#[derive(Debug)]
pub struct NetDevice {
    pub index: usize,
    pub name: String,
    pub ty: NetDeviceType,
    pub mtu: usize,
    pub flags: u16,
    pub header_len: u16,
    pub addr_len: u16,
    pub hw_addr: [u8; NET_DEVICE_ADDR_LEN],
    pub cast_type: CastType,
    pub ops: NetDeviceOps,
    pub driver: Option<DriverType>,
    pub irq_entry: IrqEntry,
    pub queue: NetDeviceQueueEntry,
    pub interfaces: LinkedList<Arc<Ipv4Interface>>,
}

impl NetDevice {
    pub fn open(&mut self) -> anyhow::Result<()> {
        debug!("open device, dev: {}", self.name);
        if self.is_up() {
            anyhow::bail!("device is already up, dev: {}", self.name);
        }

        if let Err(err) = (self.ops.open)(self) {
            return Err(err);
        }

        self.flags |= NET_DEVICE_FLAG_UP;
        info!("opened device, dev: {}, state: {}", self.name, self.state());
        return Ok(());
    }

    fn is_up(&self) -> bool {
        self.flags & NET_DEVICE_FLAG_UP != 0
    }

    fn state(&self) -> String {
        if self.is_up() {
            "UP".to_string()
        } else {
            "DOWN".to_string()
        }
    }

    pub fn close(&mut self) -> anyhow::Result<()> {
        if !self.is_up() {
            anyhow::bail!("device is already down, dev: {}", self.name);
        }

        if let Err(err) = (self.ops.close)(self) {
            return Err(err);
        }

        self.flags &= !NET_DEVICE_FLAG_UP;
        info!("closed device, dev: {}, state: {}", self.name, self.state());
        return Ok(());
    }

    pub fn register_interface(&mut self, interface: Arc<Ipv4Interface>) {
        self.interfaces.push_back(interface);
    }

    pub fn get_interface(&self, family: NetInterfaceFamily) -> Option<Arc<Ipv4Interface>> {
        for interface in self.interfaces.iter() {
            if interface.family == family {
                return Some(interface.clone());
            }
        }
        return None;
    }

    #[tracing::instrument(skip(self, data))]
    pub fn send(
        &mut self,
        data: &[u8],
        ty: NetProtocolType,
        dst: [u8; NET_DEVICE_ADDR_LEN],
    ) -> anyhow::Result<()> {
        if !self.is_up() {
            anyhow::bail!("device not opened, name: {}", self.name);
        }

        if data.len() > self.mtu {
            anyhow::bail!(
                "too long packet, dev: {}, len: {}, mtu: {}",
                self.name,
                data.len(),
                self.mtu
            );
        }

        if let Err(err) = (self.ops.transmit)(self, data, ty, dst) {
            return Err(err);
        }
        return Ok(());
    }

    #[tracing::instrument(skip_all)]
    pub fn handle_isr(&mut self, protocols: &mut NetProtocols) -> anyhow::Result<()> {
        let (protocol, payload) = match self.ty {
            NetDeviceType::Null => {
                return Ok(());
            }
            NetDeviceType::Loopback => loopback::recv(self)?,
            NetDeviceType::Ethernet => ethernet::recv(self)?,
        };
        debug!(
            "net device recv, protocol: {:?}, len: {}",
            protocol,
            payload.len()
        );

        for p in protocols.iter() {
            if p.protocol_type == protocol {
                let mut queue = p.queue.lock().unwrap();
                let Some(interface) = self.get_interface(p.protocol_type.to_family()) else {
                    anyhow::bail!("ipv4 interface not found, dev: {}", self.name);
                };
                queue.push_back(Ipv4QueueEntry {
                    data: payload,
                    interface,
                });
                debug!("net protocol queue pushed, len: {}", queue.len());
                break;
            }
        }

        raise(INTR_IRQ_L3)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NetDeviceOps {
    pub open: fn(dev: &mut NetDevice) -> anyhow::Result<()>,
    pub close: fn(dev: &mut NetDevice) -> anyhow::Result<()>,
    pub transmit: fn(
        dev: &mut NetDevice,
        data: &[u8],
        ty: NetProtocolType,
        dst: [u8; NET_DEVICE_ADDR_LEN],
    ) -> anyhow::Result<()>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_device() {
        let mut devices = NetDevices::new();
        devices.push_back(Arc::new(Mutex::new(NetDevice::null())));
        devices.push_back(Arc::new(Mutex::new(NetDevice::null())));
        devices.push_back(Arc::new(Mutex::new(NetDevice::null())));

        run_net(&mut devices).unwrap();
        let mut iter = devices.iter();
        assert_eq!(
            iter.next().unwrap().lock().unwrap().flags,
            NET_DEVICE_FLAG_UP
        );
        assert_eq!(
            iter.next().unwrap().lock().unwrap().flags,
            NET_DEVICE_FLAG_UP
        );
        assert_eq!(
            iter.next().unwrap().lock().unwrap().flags,
            NET_DEVICE_FLAG_UP
        );
    }

    #[test]
    fn close_device() {
        let mut devices = NetDevices::new();
        devices.push_back(Arc::new(Mutex::new(NetDevice::null())));
        devices.push_back(Arc::new(Mutex::new(NetDevice::null())));
        devices.push_back(Arc::new(Mutex::new(NetDevice::null())));

        run_net(&mut devices).unwrap();
        stop_net(&mut devices).unwrap();
        let mut iter = devices.iter();
        assert_eq!(iter.next().unwrap().lock().unwrap().flags, 0x0000);
        assert_eq!(iter.next().unwrap().lock().unwrap().flags, 0x0000);
        assert_eq!(iter.next().unwrap().lock().unwrap().flags, 0x0000);
    }
}
