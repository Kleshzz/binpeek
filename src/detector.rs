pub fn detect_str(data: &[u8]) -> String {
    if data.len() < 4 {
        return "Unknown (too small)".to_string();
    }
    match &data[..4] {
        [0x4D, 0x5A, ..] => "PE (Windows Executable)".to_string(),
        [0x7F, 0x45, 0x4C, 0x46] => "ELF (Linux/Unix)".to_string(),
        [0xCE, 0xFA, 0xED, 0xFE] | [0xCF, 0xFA, 0xED, 0xFE] => "Mach-O (macOS)".to_string(),
        [0x50, 0x4B, 0x03, 0x04] => "ZIP / JAR / APK".to_string(),
        [0xCA, 0xFE, 0xBA, 0xBE] => "Java .class".to_string(),
        _ => "Unknown".to_string(),
    }
}
