use log::debug;
use signal_hook::consts::SIGUSR1;

use crate::devices::{NetDevice, NetDeviceOps, NET_DEVICE_ADDR_LEN};
use crate::interrupt::{IrqEntry, INTR_IRQ_SHARED};

fn open(_: &mut NetDevice) -> anyhow::Result<()> {
    Ok(())
}

fn close(_: &mut NetDevice) -> anyhow::Result<()> {
    Ok(())
}

fn transmit(
    dev: &mut NetDevice,
    ty: u16,
    data: &[u8],
    len: usize,
    dst: [u8; NET_DEVICE_ADDR_LEN],
) -> anyhow::Result<()> {
    debug!(
        "transmit packet, dev: {}, ty: {}, len: {}, dst: {:?}",
        dev.name, ty, len, dst
    );
    debug!("data: {:?}", data);
    Ok(())
}

impl NetDevice {
    pub fn dummy() -> NetDevice {
        let irq_entry = IrqEntry {
            irq: SIGUSR1,
            flags: INTR_IRQ_SHARED,
        };

        NetDevice {
            index: 0,
            name: "dummy".to_string(),
            ty: crate::devices::NET_DEVICE_TYPE_DUMMY,
            mtu: 1500,
            flags: 0,
            header_len: 0,
            addr_len: 0,
            hw_addr: [0; NET_DEVICE_ADDR_LEN],
            cast_type: crate::devices::CastType::Peer([0; NET_DEVICE_ADDR_LEN]),
            ops: NetDeviceOps {
                open,
                close,
                transmit,
            },
            irq_entry,
        }
    }
}
