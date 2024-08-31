use std::{
    sync::mpsc,
    thread::{sleep, spawn},
    time::Duration,
};

use devices::NetDevice;
use log::{error, info};
use signal_hook::{
    consts::{SIGINT, SIGTERM, TERM_SIGNALS},
    iterator::Signals,
};

mod devices;

fn main() {
    env_logger::init();

    if let Err(e) = devices::init_net() {
        error!("init net failed: {:?}", e);
        return;
    }

    let (tx, rx) = mpsc::channel();
    let mut signals = Signals::new(TERM_SIGNALS).unwrap();
    let handle = signals.handle();
    let thread = spawn(move || {
        for signal in &mut signals {
            match signal {
                SIGTERM | SIGINT => {
                    info!("terminating app");
                    break;
                }
                _ => {}
            }
        }
        tx.send(()).unwrap();
    });

    let mut dev = NetDevice::dummy();
    dev.register(NetDevice::dummy());
    if let Err(err) = devices::run_net(&mut dev) {
        error!("run net failed: {:?}", err);
        return;
    }

    let data = [0x01, 0x02, 0x03, 0x04, 0x05];
    while rx.try_recv().is_err() {
        if let Err(err) = dev.transmit(
            0x0800,
            &data,
            data.len(),
            [0xff; devices::NET_DEVICE_ADDR_LEN],
        ) {
            error!("transmit packet failed: {:?}", err);
            break;
        }
        sleep(Duration::from_secs(1));
    }

    if let Err(err) = devices::stop_net(&mut dev) {
        error!("stop net failed: {:?}", err);
    }
    handle.close();
    thread.join().unwrap();
}
