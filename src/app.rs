use std::{
    sync::{mpsc, Arc, Barrier, Mutex},
    thread::{sleep, JoinHandle},
    time::Duration,
};

use log::{error, info};

use crate::{
    devices::{run_net, stop_net, NetDevice, NetDevices},
    protocols::{
        ipv4::{Ipv4Address, Ipv4Interface},
        NetProtocol, NetProtocols, ProtocolStackContext,
    },
    transport::{
        icmp,
        udp::{self, bind},
        ContextBlocks, Endpoint,
    },
};

pub struct App {
    devices: Arc<Mutex<NetDevices>>,
    protocols: Arc<Mutex<NetProtocols>>,
    context: Arc<Mutex<ProtocolStackContext>>,
    pcbs: Arc<Mutex<ContextBlocks>>,
}

impl App {
    pub fn new() -> Self {
        let mut context = ProtocolStackContext::new();
        let lo = Arc::new(Mutex::new(NetDevice::loopback()));
        let interface = Arc::new(Ipv4Interface::new(
            Ipv4Address::new(&[127, 0, 0, 1]),
            Ipv4Address::new(&[255, 0, 0, 0]),
            lo.clone(),
        ));
        lo.lock()
            .unwrap()
            .register_interface(&mut context, interface.clone());

        let eth = Arc::new(Mutex::new(NetDevice::ethernet_tap()));
        let interface = Arc::new(Ipv4Interface::new(
            Ipv4Address::new(&[192, 0, 2, 2]),
            Ipv4Address::new(&[255, 255, 255, 0]),
            eth.clone(),
        ));
        eth.lock()
            .unwrap()
            .register_interface(&mut context, interface.clone());

        context
            .router
            .register_default(interface, Ipv4Address::new(&[192, 0, 2, 1]));

        let mut devices = NetDevices::new();
        devices.push_back(lo);
        devices.push_back(eth);
        run_net(&mut devices).unwrap();

        let mut protocols = NetProtocols::new();
        protocols.push_back(NetProtocol::ipv4());
        protocols.push_back(NetProtocol::arp());

        App {
            devices: Arc::new(Mutex::new(devices)),
            protocols: Arc::new(Mutex::new(protocols)),
            context: Arc::new(Mutex::new(context)),
            pcbs: Arc::new(Mutex::new(ContextBlocks::new())),
        }
    }

    pub fn run(&self, rx: mpsc::Receiver<()>, barrier: Arc<Barrier>) -> JoinHandle<()> {
        info!("running app");
        let context = self.context.clone();
        let pcbs = self.pcbs.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let data = [
                /*0x45, 0x00, 0x00, 0x30, 0x00, 0x80, 0x00, 0x00, 0xff, 0x01, 0xbd, 0x4a, 0x7f, 0x00,
                0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,*/
                /*0x08, 0x00, 0x35, 0x64, 0x00, 0x80, 0x00, 0x01,*/
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x21, 0x40, 0x23, 0x24,
                0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29,
            ];
            let src = Endpoint::new(&[0, 0, 0, 0], 8000);
            let dst = Endpoint::new(&[127, 0, 0, 1], 8001);
            let mut pcbs = pcbs.lock().unwrap();
            bind(&mut pcbs, &src).unwrap();
            drop(pcbs);
            while rx.try_recv().is_err() {
                // let mut context = context.lock().unwrap();
                // if let Err(err) = udp::send(&mut context, &data, src, dst) {
                //     log::error!("transmit packet failed: {:?}", err);
                // }
                // drop(context);
                sleep(Duration::from_secs(1));
            }
        })
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
        let mut pcbs = self.pcbs.lock().unwrap();
        for protocol in self.protocols.lock().unwrap().iter() {
            log::debug!("handle irq, protocol: {:?}", protocol.protocol_type);
            if let Err(err) = protocol.recv(&mut context, &mut pcbs) {
                error!("handle irq failed: {:?}", err);
            }
        }
    }
}
