use std::{
    sync::{mpsc, Arc, Barrier, Mutex},
    thread::{sleep, JoinHandle},
    time::Duration,
};

use log::info;

use crate::{
    devices::{run_net, stop_net, NetDevice, NetDevices},
    interrupt::INTR_IRQ_DUMMY,
};

pub struct App {
    devices: Arc<Mutex<NetDevices>>,
}

impl App {
    pub fn new() -> Self {
        let mut devices = NetDevices::new();
        devices.push_back(NetDevice::dummy());
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
            signal_hook::low_level::raise(INTR_IRQ_DUMMY).unwrap();
            let data = [0x01, 0x02, 0x03, 0x04, 0x05];
            while rx.try_recv().is_err() {
                let mut devices = devices.lock().unwrap();
                let front = devices.front_mut().unwrap();
                if let Err(err) = front.transmit(
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
                dev.handle_isr();
                break;
            }
        }
    }
}
