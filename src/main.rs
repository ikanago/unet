use std::sync::{mpsc, Arc, Barrier};

use app::App;
use interrupt::INTR_IRQ_DUMMY;
use log::{debug, error, info};
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

mod app;
mod devices;
mod interrupt;

fn main() {
    env_logger::init();

    if let Err(e) = devices::init_net() {
        error!("init net failed: {:?}", e);
        return;
    }

    let (tx, rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(2));
    let app = App::new();
    let app_join = app.run(rx, barrier.clone());

    let mut signals = vec![INTR_IRQ_DUMMY];
    signals.extend(TERM_SIGNALS);
    debug!("signals: {:?}", signals);
    let mut signals = Signals::new(signals).unwrap();
    let handle = signals.handle();
    // Without waiting for the barrier, a signal may be sent before the app is ready to handle it.
    barrier.wait();
    for signal in signals.forever() {
        debug!("received signal: {}", signal);
        if TERM_SIGNALS.contains(&signal) {
            info!("terminating app");
            break;
        }
        app.handle_irq(signal);
    }

    tx.send(()).unwrap();
    app_join.join().unwrap();
    handle.close();
    app.stop();
}
