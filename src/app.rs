use std::{
    sync::{mpsc, Arc, Barrier, Mutex},
    thread::{sleep, JoinHandle},
    time::Duration,
};

use log::{error, info};

use crate::{
    devices::{run_net, stop_net, NetDevice, NetDevices},
    protocols::{
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
        let mut context = NetProtocolContext::new();
        let lo = Arc::new(Mutex::new(NetDevice::loopback()));
        let interface = Arc::new(Ipv4Interface::new(
            Ipv4Address::try_from("127.0.0.1").unwrap(),
            Ipv4Address::try_from("255.0.0.0").unwrap(),
            lo.clone(),
        ));
        lo.lock().unwrap().register_interface(interface.clone());
        let mut devices = NetDevices::new();
        devices.push_back(lo);
        context.router.register(IpRoute::new(
            Ipv4Address::try_from("127.0.0.1").unwrap(),
            interface,
        ));

        let eth = Arc::new(Mutex::new(NetDevice::ethernet_tap()));
        let interface = Arc::new(Ipv4Interface::new(
            Ipv4Address::try_from("192.0.2.2").unwrap(),
            Ipv4Address::try_from("255.255.255.0").unwrap(),
            eth.clone(),
        ));
        eth.lock().unwrap().register_interface(interface.clone());
        devices.push_back(eth);
        context.router.register(IpRoute::new(
            Ipv4Address::try_from("192.0.2.1").unwrap(),
            interface,
        ));

        run_net(&mut devices).unwrap();

        let mut protocols = NetProtocols::new();
        protocols.push_back(NetProtocol::ipv4());
        protocols.push_back(NetProtocol::arp());

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
                /*0x45, 0x00, 0x00, 0x30, 0x00, 0x80, 0x00, 0x00, 0xff, 0x01, 0xbd, 0x4a, 0x7f, 0x00,
                0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,*/
                /*0x08, 0x00, 0x35, 0x64, 0x00, 0x80, 0x00, 0x01,*/
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x21, 0x40, 0x23, 0x24,
                0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29,
            ];
            let src = Ipv4Address::try_from("127.0.0.1").unwrap();
            let dst = src.clone();
            while rx.try_recv().is_err() {
                // let mut context = context.lock().unwrap();
                // if let Err(err) = crate::transport::icmp::output(
                //     &mut context,
                //     crate::transport::icmp::IcmpType::Echo,
                //     0,
                //     42,
                //     &data,
                //     src,
                //     dst,
                // ) {
                //     log::error!("transmit packet failed: {:?}", err);
                //     break;
                // }
                // drop(context);
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

    #[tracing::instrument(skip_all)]
    pub fn handle_irq_l2(&self, irq: i32) {
        for device in self.devices.lock().unwrap().iter() {
            let mut device = device.lock().unwrap();
            if device.irq_entry.irq == irq {
                let mut protocols = self.protocols.lock().unwrap();
                if let Err(err) = device.handle_isr(&mut protocols) {
                    error!("handle irq failed: {:?}", err);
                }
                break;
            }
        }
    }

    #[tracing::instrument(skip_all)]
    pub fn handle_irq_l3(&mut self) {
        let mut context = self.context.lock().unwrap();
        for protocol in self.protocols.lock().unwrap().iter() {
            if let Err(err) = protocol.recv(&mut context) {
                error!("handle irq failed: {:?}", err);
            }
        }
    }
}
