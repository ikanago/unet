use std::sync::{mpsc, Arc, Barrier};

use app::App;
use interrupt::{INTR_IRQ_ETHERNET_TAP, INTR_IRQ_L3, INTR_IRQ_LOOPBACK, INTR_IRQ_NULL};
use log::{debug, error, info};
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

mod app;
mod devices;
mod driver;
mod interrupt;
mod protocols;
mod transport;
mod utils;

fn main() {
    // env_logger::init();

    tracing_log::LogTracer::init().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    if let Err(e) = devices::init_net() {
        error!("init net failed: {:?}", e);
        return;
    }

    let (tx, rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(2));
    let mut app = App::new();
    let app_join = app.run(rx, barrier.clone());

    let mut signals = vec![
        INTR_IRQ_NULL,
        INTR_IRQ_LOOPBACK,
        INTR_IRQ_ETHERNET_TAP,
        INTR_IRQ_L3,
    ];
    signals.extend(TERM_SIGNALS);
    debug!("signals: {:?}", signals);
    let mut signals = Signals::new(signals).unwrap();
    let handle = signals.handle();
    // Without waiting for the barrier, a signal may be sent before the app is ready to handle it.
    barrier.wait();
    for signal in signals.forever() {
        match signal {
            INTR_IRQ_NULL | INTR_IRQ_LOOPBACK | INTR_IRQ_ETHERNET_TAP => app.handle_irq_l2(signal),
            INTR_IRQ_L3 => app.handle_irq_l3(),
            signal if TERM_SIGNALS.contains(&signal) => {
                info!("terminating app");
                break;
            }
            _ => {}
        }
    }

    tx.send(()).unwrap();
    app_join.join().unwrap();
    handle.close();
    app.stop();
}
