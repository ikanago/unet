use std::{
    sync::{mpsc, Arc, Barrier, Mutex},
    thread::{sleep, JoinHandle},
    time::Duration,
};

use log::{error, info};

use crate::{
    devices::{run_net, stop_net, NetDevice, NetDevices},
    protocols::{
        self,
        ipv4::{IpRoute, Ipv4Address, Ipv4Interface},
        NetProtocol, NetProtocolContext, NetProtocols,
    },
};

pub struct App {
    devices: Arc<Mutex<NetDevices>>,
    protocols: Arc<Mutex<NetProtocols>>,
    context: Arc<Mutex<NetProtocolContext>>,
}

impl App {
    pub fn new() -> Self {
        let lo = Arc::new(Mutex::new(NetDevice::loopback()));
        let interface = Arc::new(Ipv4Interface::new(
            Ipv4Address::try_from("127.0.0.1").unwrap(),
            Ipv4Address::try_from("255.0.0.0").unwrap(),
            lo.clone(),
        ));
        lo.lock().unwrap().register_interface(interface.clone());
        let mut devices = NetDevices::new();
        devices.push_back(lo);
        run_net(&mut devices).unwrap();

        let mut context = NetProtocolContext::new();
        context.router.register(IpRoute::new(
            Ipv4Address::try_from("127.0.0.1").unwrap(),
            interface,
        ));

        let mut protocols = NetProtocols::new();
        protocols.push_back(NetProtocol::ipv4());

        App {
            devices: Arc::new(Mutex::new(devices)),
            protocols: Arc::new(Mutex::new(protocols)),
            context: Arc::new(Mutex::new(context)),
        }
    }

    pub fn run(&self, rx: mpsc::Receiver<()>, barrier: Arc<Barrier>) -> JoinHandle<()> {
        info!("running app");
        let context = self.context.clone();
        let handle = std::thread::spawn(move || {
            barrier.wait();
            let data = [
                0x45, 0x00, 0x00, 0x30, 0x00, 0x80, 0x00, 0x00, 0xff, 0x01, 0xbd, 0x4a, 0x7f, 0x00,
                0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x35, 0x64, 0x00, 0x80, 0x00, 0x01,
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x21, 0x40, 0x23, 0x24,
                0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29,
            ];
            let src = Ipv4Address::try_from("127.0.0.1").unwrap();
            let dst = src.clone();
            while rx.try_recv().is_err() {
                let mut context = context.lock().unwrap();
                if let Err(err) = protocols::ipv4::output(&mut context, &data, src, dst) {
                    log::error!("transmit packet failed: {:?}", err);
                    break;
                }
                drop(context);
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
        for device in self.devices.lock().unwrap().iter() {
            let device = device.lock().unwrap();
            if device.irq_entry.irq == irq {
                let mut protocols = self.protocols.lock().unwrap();
                if let Err(err) = device.handle_isr(&mut protocols) {
                    error!("handle irq failed: {:?}", err);
                }
                break;
            }
        }
    }

    pub fn handle_irq_l3(&mut self) {
        for protocol in self.protocols.lock().unwrap().iter() {
            let mut context = self.context.lock().unwrap();
            if let Err(err) = protocol.handle_isr(&mut context) {
                error!("handle irq failed: {:?}", err);
            }
        }
    }
}
