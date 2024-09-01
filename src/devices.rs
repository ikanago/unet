pub mod dummy;

use std::collections::LinkedList;

use anyhow::Ok;
use log::{debug, info};

use crate::interrupt::IrqEntry;

pub const NET_DEVICE_TYPE_DUMMY: u16 = 0x0000;

const NET_DEVICE_FLAG_UP: u16 = 0x0001;
const NET_DEVICE_FLAG_LOOPBACK: u16 = 0x0010;
const NET_DEVICE_FLAG_BROADCAST: u16 = 0x0020;
const NET_DEVICE_FLAG_P2P: u16 = 0x0040;
const NET_DEVICE_FLAG_NEED_ARP: u16 = 0x0100;

pub const NET_DEVICE_ADDR_LEN: usize = 16;

pub fn run_net(devices: &mut NetDevices) -> anyhow::Result<()> {
    info!("open all devices");
    for dev in devices.iter_mut() {
        dev.open()?;
    }
    return Ok(());
}

pub fn stop_net(devices: &mut NetDevices) -> anyhow::Result<()> {
    info!("close all devices");
    for dev in devices.iter_mut() {
        dev.close()?;
    }
    return Ok(());
}

pub fn init_net() -> anyhow::Result<()> {
    Ok(())
}

pub fn net_input_handler(ty: u16, data: &[u8], len: usize) -> anyhow::Result<()> {
    Ok(())
}

pub type NetDevices = LinkedList<NetDevice>;

#[derive(Debug, Clone)]
pub enum CastType {
    Peer([u8; NET_DEVICE_ADDR_LEN]),
    Broadcast([u8; NET_DEVICE_ADDR_LEN]),
}

#[derive(Debug, Clone)]
pub struct NetDevice {
    pub index: usize,
    pub name: String,
    pub ty: u16,
    pub mtu: usize,
    pub flags: u16,
    pub header_len: u16,
    pub addr_len: u16,
    pub hw_addr: [u8; NET_DEVICE_ADDR_LEN],
    pub cast_type: CastType,
    pub ops: NetDeviceOps,
    pub irq_entry: IrqEntry,
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

    pub fn transmit(
        &mut self,
        ty: u16,
        data: &[u8],
        len: usize,
        dst: [u8; NET_DEVICE_ADDR_LEN],
    ) -> anyhow::Result<()> {
        if !self.is_up() {
            anyhow::bail!("device not opened, name: {}", self.name);
        }

        if len > self.mtu {
            anyhow::bail!(
                "too long packet, dev: {}, len: {}, mtu: {}",
                self.name,
                len,
                self.mtu
            );
        }

        if let Err(err) = (self.ops.transmit)(self, ty, data, len, dst) {
            return Err(err);
        }
        return Ok(());
    }

    pub fn handle_isr(&self) {
        debug!(
            "handle interrupt, dev: {}, irq: {}",
            self.name, self.irq_entry.irq
        );
    }
}

#[derive(Debug, Clone)]
pub struct NetDeviceOps {
    pub open: fn(dev: &mut NetDevice) -> anyhow::Result<()>,
    pub close: fn(dev: &mut NetDevice) -> anyhow::Result<()>,
    pub transmit: fn(
        dev: &mut NetDevice,
        ty: u16,
        data: &[u8],
        len: usize,
        dst: [u8; NET_DEVICE_ADDR_LEN],
    ) -> anyhow::Result<()>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_device() {
        let mut devices = NetDevices::new();
        devices.push_back(NetDevice::dummy());
        devices.push_back(NetDevice::dummy());
        devices.push_back(NetDevice::dummy());

        run_net(&mut devices).unwrap();
        let mut iter = devices.iter();
        assert_eq!(iter.next().unwrap().flags, NET_DEVICE_FLAG_UP);
        assert_eq!(iter.next().unwrap().flags, NET_DEVICE_FLAG_UP);
        assert_eq!(iter.next().unwrap().flags, NET_DEVICE_FLAG_UP);
    }

    #[test]
    fn close_device() {
        let mut devices = NetDevices::new();
        devices.push_back(NetDevice::dummy());
        devices.push_back(NetDevice::dummy());
        devices.push_back(NetDevice::dummy());

        run_net(&mut devices).unwrap();
        stop_net(&mut devices).unwrap();
        let mut iter = devices.iter();
        assert_eq!(iter.next().unwrap().flags, 0x0000);
        assert_eq!(iter.next().unwrap().flags, 0x0000);
        assert_eq!(iter.next().unwrap().flags, 0x0000);
    }
}
