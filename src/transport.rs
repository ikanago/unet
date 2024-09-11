pub mod icmp;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProtocolNumber {
    Icmp = 1,
}

impl TryFrom<u8> for TransportProtocolNumber {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TransportProtocolNumber::Icmp),
            _ => Err(anyhow::anyhow!("unknown ip protocol number: {}", value)),
        }
    }
}
