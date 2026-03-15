pub fn detect_str(data: &[u8]) -> String {
    if data.len() < 4 {
        return "Unknown (too small)".to_string();
    }
    match &data[..4] {
        // Executables
        [0x7F, 0x45, 0x4C, 0x46]                     => "ELF (Linux/Unix)".to_string(),
        [0x4D, 0x5A, ..]                             => "PE (Windows Executable)".to_string(),
        [0xCE, 0xFA, 0xED, 0xFE] |  // 32-bit little-endian
        [0xCF, 0xFA, 0xED, 0xFE] |  // 64-bit little-endian
        [0xFE, 0xED, 0xFA, 0xCE] |  // 32-bit big-endian
        [0xFE, 0xED, 0xFA, 0xCF]                     => "Mach-O (macOS)".to_string(),
        [0xCA, 0xFE, 0xBA, 0xBE]                     => "Java .class".to_string(),
        [0x00, 0x61, 0x73, 0x6D]                     => "WebAssembly (.wasm)".to_string(),

        // Archives
        [0x50, 0x4B, 0x03, 0x04]                     => "ZIP / JAR / APK / DOCX".to_string(),
        [0x52, 0x61, 0x72, 0x21]                     => "RAR Archive".to_string(),
        [0x1F, 0x8B, ..]                             => "GZIP".to_string(),
        [0x42, 0x5A, 0x68, ..]                       => "BZIP2".to_string(),
        [0xFD, 0x37, 0x7A, 0x58]                     => "XZ Archive".to_string(),
        [0x37, 0x7A, 0xBC, 0xAF]                     => "7-Zip Archive".to_string(),
        [0x1F, 0x9D, ..]                             => "TAR (compressed)".to_string(),

        // Images
        [0xFF, 0xD8, 0xFF, ..]                       => "JPEG Image".to_string(),
        [0x89, 0x50, 0x4E, 0x47]                     => "PNG Image".to_string(),
        [0x47, 0x49, 0x46, 0x38]                     => "GIF Image".to_string(),
        [0x42, 0x4D, ..]                             => "BMP Image".to_string(),
        [0x49, 0x49, 0x2A, 0x00] |
        [0x4D, 0x4D, 0x00, 0x2A]                     => "TIFF Image".to_string(),
        [0x57, 0x45, 0x42, 0x50]                     => "WebP Image".to_string(),

        // Documents
        [0x25, 0x50, 0x44, 0x46]                     => "PDF Document".to_string(),
        [0x7B, 0x5C, 0x72, 0x74]                     => "RTF Document".to_string(),
        [0xD0, 0xCF, 0x11, 0xE0]                     => "MS Office (DOC / XLS / PPT)".to_string(),

        // Audio
        [0x49, 0x44, 0x33, ..]                       => "MP3 Audio".to_string(),
        [0x4F, 0x67, 0x67, 0x53]                     => "OGG Audio".to_string(),
        [0x66, 0x4C, 0x61, 0x43]                     => "FLAC Audio".to_string(),
        [0x52, 0x49, 0x46, 0x46]                     => "RIFF (WAV / AVI)".to_string(),

        // Video
        [0x66, 0x74, 0x79, 0x70]                     => "MP4 / MOV Video".to_string(),

        // System / Windows
        [0x4C, 0x00, 0x00, 0x00]                     => "Windows Shortcut (.lnk)".to_string(),
        [0x4D, 0x53, 0x43, 0x46]                     => "Windows Cabinet (.cab)".to_string(),
        [0x52, 0x45, 0x47, 0x46]                     => "Windows Registry Hive".to_string(),
        [0x4D, 0x44, 0x4D, 0x50]                     => "Windows Minidump (.dmp)".to_string(),

        // Databases
        [0x53, 0x51, 0x4C, 0x69]                     => "SQLite Database".to_string(),

        _ => "Unknown".to_string(),
    }
}
