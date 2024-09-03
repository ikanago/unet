pub const INTR_IRQ_SHARED: u8 = 0x01;

pub const INTR_IRQ_BASE: i32 = 35; // SIGRTMIN + 1
pub const INTR_IRQ_NULL: i32 = INTR_IRQ_BASE;
pub const INTR_IRQ_LOOPBACK: i32 = INTR_IRQ_BASE + 1;
pub const INTR_IRQ_L3: i32 = INTR_IRQ_BASE + 2;

#[derive(Clone, Debug)]
pub struct IrqEntry {
    pub irq: i32,
    pub flags: u8,
}
