use std::{
    sync::{mpsc, Arc, Barrier, Mutex},
    thread::{sleep, JoinHandle},
    time::Duration,
};

use log::{error, info};

use crate::devices::{run_net, stop_net, NetDevice, NetDevices};

pub struct App {
    devices: Arc<Mutex<NetDevices>>,
}

impl App {
    pub fn new() -> Self {
        let mut devices = NetDevices::new();
        devices.push_back(NetDevice::loopback());
        run_net(&mut devices).unwrap();

        App {
            devices: Arc::new(Mutex::new(devices)),
        }
    }

    pub fn run(&self, rx: mpsc::Receiver<()>, barrier: Arc<Barrier>) -> JoinHandle<()> {
        let devices = self.devices.clone();
        info!("running app");
        let handle = std::thread::spawn(move || {
            barrier.wait();
            let data = [0x01, 0x02, 0x03, 0x04, 0x05];
            while rx.try_recv().is_err() {
                let mut devices = devices.lock().unwrap();
                let device = devices.front_mut().unwrap();
                if let Err(err) = device.transmit(
                    0x0800,
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

    pub fn handle_irq(&self, irq: i32) {
        for dev in self.devices.lock().unwrap().iter() {
            if dev.irq_entry.irq == irq {
                if let Err(err) = dev.handle_isr() {
                    error!("handle irq failed: {:?}", err);
                }
                break;
            }
        }
    }
}
