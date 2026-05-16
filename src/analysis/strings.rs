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
        }
    }
    if current.len() >= min_len {
        results.push(String::from_utf8(current).unwrap());
    }

    results.dedup();
    results.truncate(10_000);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(extract(&[], 4).is_empty());
    }

    #[test]
    fn min_len_filter() {
        let data = b"hi\x00hello\x00toolong";
        let r = extract(data, 5);
        assert!(!r.contains(&"hi".to_string()));
        assert!(r.contains(&"hello".to_string()));
        assert!(r.contains(&"toolong".to_string()));
    }

    #[test]
    fn null_separated_strings() {
        let data = b"foo\x00bar\x00baz";
        let r = extract(data, 3);
        assert_eq!(r, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn truncates_at_10000() {
        // each string = "aaaaa" + null separator
        let mut data = Vec::new();
        for _ in 0..15_000 {
            data.extend_from_slice(b"aaaaa\x00");
        }
        let r = extract(&data, 5);
        assert!(r.len() <= 10_000);
    }

    #[test]
    fn no_control_bytes_in_output() {
        let data: Vec<u8> = (0u8..=255).collect();
        for s in extract(&data, 1) {
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_graphic() || c == ' ' || c == '\t')
            );
        }
    }
}
