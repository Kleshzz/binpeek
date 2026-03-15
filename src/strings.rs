pub fn extract(data: &[u8], min_len: usize) -> Vec<String> {
    let data = if data.len() > 100_000_000 {
        &data[..100_000_000]
    } else {
        data
    };
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&current) {
                    results.push(s.to_string());
                    if results.len() >= 10_000 {
                        results.push("  ... truncated (too many strings)".to_string());
                        break;
                    }
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&current) {
            results.push(s.to_string());
        }
    }

    results
}
