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
