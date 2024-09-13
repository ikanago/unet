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

// Safety: Returning type T should be defined as #[repr(packed)].
pub unsafe fn bytes_to_struct<T>(data: &[u8]) -> T {
    let t: T = std::ptr::read(data.as_ptr() as *const T);
    t
}

// Safety: Converted type T should be defined as #[repr(packed)].
pub unsafe fn struct_to_bytes<T>(t: &T) -> &[u8] {
    let ptr = t as *const T as *const u8;
    std::slice::from_raw_parts(ptr, std::mem::size_of::<T>())
}
