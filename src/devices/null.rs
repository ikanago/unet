use log::debug;
use signal_hook::consts::SIGUSR1;

use crate::devices::{NetDevice, NetDeviceOps, NET_DEVICE_ADDR_LEN};
use crate::interrupt::{IrqEntry, INTR_IRQ_SHARED};
use crate::protocols::NetProtocolType;

use super::ethernet::MacAddress;
use super::NetDeviceQueueEntry;

fn open(_: &mut NetDevice) -> anyhow::Result<()> {
    Ok(())
}

fn close(_: &mut NetDevice) -> anyhow::Result<()> {
    Ok(())
}

fn transmit(
    dev: &mut NetDevice,
    data: &[u8],
    _ty: NetProtocolType,
    dst: MacAddress,
) -> anyhow::Result<()> {
    debug!("transmit packet, dev: {}, dst: {:?}", dev.name, dst);
    debug!("data: {:?}", data);
    Ok(())
}

impl NetDevice {
    pub fn null() -> NetDevice {
        let irq_entry = IrqEntry {
            irq: SIGUSR1,
            flags: INTR_IRQ_SHARED,
        };

        NetDevice {
            index: 0,
            name: "null".to_string(),
            ty: super::NetDeviceType::Null,
            mtu: 1500,
            flags: 0,
            header_len: 0,
            addr_len: 0,
            hw_addr: [0; NET_DEVICE_ADDR_LEN],
            cast_type: crate::devices::CastType::Peer([0; NET_DEVICE_ADDR_LEN]),
            ops: NetDeviceOps {
                open,
                close,
                send: transmit,
            },
            driver: None,
            irq_entry,
            queue: NetDeviceQueueEntry::Null,
            interfaces: Default::default(),
        }
    }
}
