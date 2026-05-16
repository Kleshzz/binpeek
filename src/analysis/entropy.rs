pub fn calculate(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn label(entropy: f64) -> &'static str {
    if entropy <= 2.0 {
        "plain text / very low"
    } else if entropy <= 5.0 {
        "normal"
    } else if entropy <= 7.0 {
        "compressed or encrypted"
    } else {
        "likely encrypted/packed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(calculate(&[]), 0.0);
    }

    #[test]
    fn single_byte_repeated_is_zero() {
        let data = vec![0xAAu8; 1000];
        assert!(calculate(&data) < 0.001);
    }

    #[test]
    fn uniform_256_bytes_is_eight() {
        let data: Vec<u8> = (0..=255).collect();
        let e = calculate(&data);
        assert!((e - 8.0).abs() < 0.01, "got {}", e);
    }

    #[test]
    fn label_ranges() {
        assert_eq!(label(0.0), "plain text / very low");
        assert_eq!(label(2.0), "plain text / very low");
        assert_eq!(label(3.5), "normal");
        assert_eq!(label(5.0), "normal");
        assert_eq!(label(6.5), "compressed or encrypted");
        assert_eq!(label(7.0), "compressed or encrypted");
        assert_eq!(label(7.5), "likely encrypted/packed");
    }
}
