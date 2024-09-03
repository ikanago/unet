use std::{
    sync::{mpsc, Arc, Barrier, Mutex},
    thread::{sleep, JoinHandle},
    time::Duration,
};

use log::{error, info};

use crate::{
    devices::{run_net, stop_net, NetDevice, NetDevices},
    protocols::{NetProtocol, NetProtocols},
};

pub struct App {
    devices: Arc<Mutex<NetDevices>>,
    protocols: Arc<Mutex<NetProtocols>>,
}

impl App {
    pub fn new() -> Self {
        let mut devices = NetDevices::new();
        devices.push_back(NetDevice::loopback());
        run_net(&mut devices).unwrap();

        let mut protocols = NetProtocols::new();
        protocols.push_back(NetProtocol::ipv4());

        App {
            devices: Arc::new(Mutex::new(devices)),
            protocols: Arc::new(Mutex::new(protocols)),
        }
    }

    pub fn run(&self, rx: mpsc::Receiver<()>, barrier: Arc<Barrier>) -> JoinHandle<()> {
        let devices = self.devices.clone();
        info!("running app");
        let handle = std::thread::spawn(move || {
            barrier.wait();
            let data = [
                0x45, 0x00, 0x00, 0x30, 0x00, 0x80, 0x00, 0x00, 0xff, 0x01, 0xbd, 0x4a, 0x7f, 0x00,
                0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x35, 0x64, 0x00, 0x80, 0x00, 0x01,
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x21, 0x40, 0x23, 0x24,
                0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29,
            ];
            while rx.try_recv().is_err() {
                let mut devices = devices.lock().unwrap();
                let device = devices.front_mut().unwrap();
                if let Err(err) = device.transmit(
                    &data,
                    data.len(),
                    [0xff; crate::devices::NET_DEVICE_ADDR_LEN],
                ) {
                    log::error!("transmit packet failed: {:?}", err);
                    break;
                }
                drop(devices);
                sleep(Duration::from_secs(1));
            }
        });
        handle
    }

    pub fn stop(&self) {
        info!("stopping app");
        let mut devices = self.devices.lock().unwrap();
        stop_net(&mut devices).unwrap();
    }

    pub fn handle_irq_l2(&self, irq: i32) {
        for dev in self.devices.lock().unwrap().iter() {
            if dev.irq_entry.irq == irq {
                let mut protocols = self.protocols.lock().unwrap();
                if let Err(err) = dev.handle_isr(&mut protocols) {
                    error!("handle irq failed: {:?}", err);
                }
                break;
            }
        }
    }

    pub fn handle_irq_l3(&self) {
        for protocol in self.protocols.lock().unwrap().iter() {
            if let Err(err) = protocol.handle_isr() {
                error!("handle irq failed: {:?}", err);
            }
        }
    }
}
