pub fn extract(data: &[u8], min_len: usize) -> Vec<String> {
    let data = if data.len() > 100_000_000 {
        &data[..100_000_000]
    } else {
        data
    };
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                results.push(String::from_utf8(std::mem::take(&mut current)).unwrap());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        results.push(String::from_utf8(current).unwrap());
    }

    results.dedup();
    results.truncate(10_000);
    results
}
