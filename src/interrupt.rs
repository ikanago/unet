pub const INTR_IRQ_SHARED: u8 = 0x01;
pub const INTR_IRQ_DUMMY: i32 = 35; // SIGRTMIN + 1

#[derive(Clone, Debug)]
pub struct IrqEntry {
    pub irq: i32,
    pub flags: u8,
}
