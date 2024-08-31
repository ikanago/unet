pub mod dummy;

use anyhow::bail;
use log::{debug, info};

const IFNAMSIZ: usize = 16;

pub const NET_DEVICE_TYPE_DUMMY: u16 = 0x0000;

const NET_DEVICE_FLAG_UP: u16 = 0x0001;
const NET_DEVICE_FLAG_LOOPBACK: u16 = 0x0010;
const NET_DEVICE_FLAG_BROADCAST: u16 = 0x0020;
const NET_DEVICE_FLAG_P2P: u16 = 0x0040;
const NET_DEVICE_FLAG_NEED_ARP: u16 = 0x0100;

pub const NET_DEVICE_ADDR_LEN: usize = 16;

pub fn run_net(dev: &mut NetDevice) -> anyhow::Result<()> {
    info!("open all devices");
    let mut p = dev;
    p.open()?;
    while let Some(dev) = p.next.as_mut() {
        dev.open()?;
        p = dev;
    }
    return Ok(());
}

pub fn stop_net(dev: &mut NetDevice) -> anyhow::Result<()> {
    info!("close all devices");
    let mut p = dev;
    p.close()?;
    while let Some(dev) = p.next.as_mut() {
        dev.close()?;
        p = dev;
    }
    return Ok(());
}

pub fn init_net() -> anyhow::Result<()> {
    Ok(())
}

pub fn net_input_handler(ty: u16, data: &[u8], len: usize) -> anyhow::Result<()> {
    Ok(())
}

#[derive(Debug, Clone)]
pub enum CastType {
    Peer([u8; NET_DEVICE_ADDR_LEN]),
    Broadcast([u8; NET_DEVICE_ADDR_LEN]),
}

#[derive(Debug, Clone)]
pub struct NetDevice {
    pub next: Option<Box<NetDevice>>,
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
    // pub priv_data: *mut c_void,
}

impl NetDevice {
    // dev -> self(net2) -> net1 -> net0 -> None
    pub fn register(&mut self, mut dev: NetDevice) {
        dev.index = self.index + 1;
        dev.name = format!("net{}", dev.index);
        let p = self.clone();
        dev.next = Some(Box::new(p));
        // dbg!(&dev);
        *self = dev;
        info!("registered device, dev: {}, type: {}", self.name, self.ty);
    }

    pub fn open(&mut self) -> anyhow::Result<()> {
        debug!("open device, dev: {}", self.name);
        if self.is_up() {
            bail!("device is already up, dev: {}", self.name);
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
            bail!("device is already down, dev: {}", self.name);
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
            bail!("device not opened, name: {}", self.name);
        }

        if len > self.mtu {
            bail!(
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
    fn test_register() {
        let mut dev = NetDevice::dummy();
        dev.register(NetDevice::dummy());
        dev.register(NetDevice::dummy());
        dev.register(NetDevice::dummy());

        assert_eq!(dev.index, 3);
        let net2 = dev.next.as_ref().unwrap();
        assert_eq!(net2.index, 2);
        let net1 = net2.next.as_ref().unwrap();
        assert_eq!(net1.index, 1);
        let net0 = net1.next.as_ref().unwrap();
        assert_eq!(net0.index, 0);
        assert!(net0.next.is_none());
    }

    #[test]
    fn open_device() {
        let mut dev = NetDevice::dummy();
        dev.register(NetDevice::dummy());
        dev.register(NetDevice::dummy());

        run_net(&mut dev).unwrap();
        assert_eq!(dev.flags, NET_DEVICE_FLAG_UP);
        let net1 = dev.next.as_ref().unwrap();
        assert_eq!(net1.flags, NET_DEVICE_FLAG_UP);
        let net0 = net1.next.as_ref().unwrap();
        assert_eq!(net0.flags, NET_DEVICE_FLAG_UP);
    }

    #[test]
    fn close_device() {
        let mut dev = NetDevice::dummy();
        dev.register(NetDevice::dummy());
        dev.register(NetDevice::dummy());

        run_net(&mut dev).unwrap();
        stop_net(&mut dev).unwrap();
        assert_eq!(dev.flags, 0x0000);
        let net1 = dev.next.as_ref().unwrap();
        assert_eq!(net1.flags, 0x0000);
        let net0 = net1.next.as_ref().unwrap();
        assert_eq!(net0.flags, 0x0000);
    }
}
