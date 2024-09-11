pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = data
        .chunks(2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]) as u32)
        .sum::<u32>();
    while sum.checked_shr(16).unwrap_or(0) != 0 {
        sum = (sum & 0xffff) + sum.checked_shr(16).unwrap_or(0);
    }
    !sum as u16
}
