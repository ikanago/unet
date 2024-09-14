use core::slice;
use std::{
    ffi::CString,
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::AsRawFd,
};

use log::{debug, info};
use nix::{
    errno::Errno,
    ioctl_read_bad, ioctl_write_int,
    libc::{
        c_int, c_short, fcntl, getpid, ifreq, F_SETFL, F_SETOWN, IFF_NO_PI, IFF_TAP, IFNAMSIZ,
        O_ASYNC,
    },
    sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType},
};

use crate::{
    devices::{
        ethernet::{
            EthernetHeader, MacAddress, ETHERNET_FRAME_MAX_SIZE, ETHERNET_FRAME_MIN_SIZE,
            ETHERNET_HEADER_SIZE, ETHERNET_PAYLOAD_MAX_SIZE, MAC_ADDRESS_ANY, MAC_ADDRESS_LEN,
        },
        CastType, NetDevice, NetDeviceOps, NetDeviceType, NET_DEVICE_ADDR_LEN,
        NET_DEVICE_FLAG_LOOPBACK, NET_DEVICE_FLAG_NEED_ARP,
    },
    interrupt::{IrqEntry, INTR_IRQ_ETHERNET_TAP},
    protocols::NetProtocolType,
};

use super::DriverType;

const TUN_PATH: &str = "/dev/net/tun";
const F_SETSIG: c_int = 10;

// You can find the definition of magic number in <linux/tun.h>
// See also: https://www.kernel.org/doc/Documentation/networking/tuntap.txt
ioctl_write_int!(tun_set_iff, b'T', 202);
ioctl_read_bad!(get_hw_addr, 0x8927, ifreq);

fn close(_device: &mut NetDevice) -> anyhow::Result<()> {
    Ok(())
}

fn open(device: &mut NetDevice) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TUN_PATH)
        .unwrap();
    let fd = file.as_raw_fd();
    device.driver = Some(DriverType::Tap { file });
    let ifru_flags = (IFF_TAP | IFF_NO_PI) as c_short;
    let ifreq = ifreq {
        ifr_name: to_ifreq_name(&device.name)?,
        ifr_ifru: nix::libc::__c_anonymous_ifr_ifru { ifru_flags },
    };
    unsafe {
        if let Err(err) = tun_set_iff(fd, &ifreq as *const ifreq as u64) {
            anyhow::bail!("tun_set_iff failed: {:?}", err);
        }
    }

    unsafe {
        // Set asynchronous I/O destination
        if fcntl(fd, F_SETOWN, getpid() as c_int) == -1 {
            anyhow::bail!("fcntl F_SETOWN failed: {}", Errno::last_raw());
        }
        // Enable asynchronous I/O
        if fcntl(fd, F_SETFL, O_ASYNC) == -1 {
            anyhow::bail!("fcntl F_SETFL failed: {}", Errno::last_raw());
        }
        // Use other signal than SIGIO
        if fcntl(fd, F_SETSIG, device.irq_entry.irq as c_int) == -1 {
            anyhow::bail!("fcntl F_SETSIG failed: {}", Errno::last_raw());
        }

        if device.hw_addr[..MAC_ADDRESS_LEN] == MAC_ADDRESS_ANY.0 {
            set_tap_address(device)?;
        }
    }
    Ok(())
}

fn to_ifreq_name(name: &str) -> anyhow::Result<[i8; IFNAMSIZ]> {
    let name_c = CString::new(name)?;
    let name_slice = name_c
        .as_bytes_with_nul()
        .iter()
        .map(|&b| b as i8)
        .collect::<Vec<_>>();
    if name_slice.len() > IFNAMSIZ {
        anyhow::bail!("device name too long: {}", name);
    }
    let mut buf = [0i8; IFNAMSIZ];
    buf[..name_slice.len()].copy_from_slice(&name_slice);
    Ok(buf)
}

fn set_tap_address(device: &mut NetDevice) -> anyhow::Result<()> {
    // Open a any socket to call get_hw_addr
    let soc = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        SockProtocol::Udp,
    )?;
    let mut ifreq = ifreq {
        ifr_name: to_ifreq_name(&device.name)?,
        ifr_ifru: unsafe { std::mem::zeroed() },
    };
    unsafe {
        if let Err(err) = get_hw_addr(soc.as_raw_fd(), &mut ifreq as *mut ifreq) {
            anyhow::bail!("get_hw_addr failed: {:?}", err);
        }
        let hw_addr_u8 = slice::from_raw_parts(
            ifreq.ifr_ifru.ifru_hwaddr.sa_data.as_ptr() as *const u8,
            NET_DEVICE_ADDR_LEN,
        );
        device.hw_addr.copy_from_slice(hw_addr_u8);
    }
    info!(
        "set hardware address for {}: {:?}",
        device.name, device.hw_addr
    );
    Ok(())
}

#[tracing::instrument(skip(device, data))]
pub fn send(
    device: &mut NetDevice,
    data: &[u8],
    ty: NetProtocolType,
    dst: [u8; NET_DEVICE_ADDR_LEN],
) -> anyhow::Result<()> {
    let header = EthernetHeader {
        dst: MacAddress::from(dst[..MAC_ADDRESS_LEN].as_ref()),
        src: MacAddress::from(device.hw_addr[..MAC_ADDRESS_LEN].as_ref()),
        ty,
    };

    let mut frame = header.to_bytes();
    frame.extend_from_slice(data);

    let len_padding = if data.len() < ETHERNET_FRAME_MIN_SIZE {
        ETHERNET_FRAME_MIN_SIZE - data.len()
    } else {
        0
    };
    frame.extend_from_slice(&vec![0; len_padding]);
    if let Some(mut driver) = device.driver.as_mut() {
        let DriverType::Tap { ref mut file } = &mut driver;
        file.write_all(&frame)?;
    }

    debug!(
        "ethernet frame transmitted, dev: {}, type: {:#04x}, len: {}",
        device.name,
        ty as u16,
        frame.len()
    );

    Ok(())
}

pub fn read(device: &mut NetDevice) -> anyhow::Result<Vec<u8>> {
    let DriverType::Tap { ref mut file } = device.driver.as_mut().expect("device driver not set");
    let mut buf = [0; ETHERNET_FRAME_MAX_SIZE];
    file.read(&mut buf)?;
    Ok(buf.to_vec())
}

impl NetDevice {
    pub fn ethernet_tap() -> Self {
        let irq_entry = IrqEntry {
            irq: INTR_IRQ_ETHERNET_TAP,
            flags: 0x00,
        };

        Self {
            index: 0,
            name: "tap0".to_string(),
            ty: NetDeviceType::Ethernet,
            mtu: ETHERNET_PAYLOAD_MAX_SIZE,
            flags: NET_DEVICE_FLAG_LOOPBACK | NET_DEVICE_FLAG_NEED_ARP,
            header_len: ETHERNET_HEADER_SIZE as u16,
            addr_len: MAC_ADDRESS_LEN as u16,
            hw_addr: [0; NET_DEVICE_ADDR_LEN],
            // cast_type: CastType::Broadcast(MAC_ADDRESS_BROADCAST),
            cast_type: CastType::Peer([0; NET_DEVICE_ADDR_LEN]),
            ops: NetDeviceOps {
                open,
                close,
                transmit: send,
            },
            driver: None,
            irq_entry,
            queue: crate::devices::NetDeviceQueueEntry::Null,
            interfaces: std::collections::LinkedList::new(),
        }
    }
}
