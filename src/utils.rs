pub fn calculate_checksum(data: &[u8], sum: u16) -> u16 {
    let mut sum = sum as u32
        + data
            .chunks(2)
            .map(|x| u16::from_be_bytes([x[0], x[1]]) as u32)
            .sum::<u32>();
    while sum.checked_shr(16).unwrap_or(0) != 0 {
        sum = (sum & 0xffff) + sum.checked_shr(16).unwrap_or(0);
    }
    !sum as u16
}

// Safety: Returning type T should be defined as #[repr(packed)].
pub unsafe fn to_struct<T: Sized>(data: &[u8]) -> &T {
    let (head, t, _) = data.align_to::<T>();
    assert!(head.is_empty());
    &t[0]
}

// Safety: Converted type T should be defined as #[repr(packed)].
pub unsafe fn to_bytes<T: Sized>(t: &T) -> &[u8] {
    let ptr = t as *const T as *const u8;
    std::slice::from_raw_parts(ptr, std::mem::size_of::<T>())
}

// Safety: Converted type T should be defined as #[repr(packed)].
pub unsafe fn to_bytes_mut<T: Sized>(t: &mut T) -> &mut [u8] {
    let ptr = t as *mut T as *mut u8;
    std::slice::from_raw_parts_mut(ptr, std::mem::size_of::<T>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_checksum() {
        let data = [
            0x1f, 0x40, 0x1f, 0x41, 0x0, 0x1c, 0x0, 0x0, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x37, 0x38, 0x39,
        ];
        let sum = calculate_checksum(&data, 0);
        assert_eq!(calculate_checksum(&data, sum), 0);
    }
}
