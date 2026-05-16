pub fn detect_with_path(data: &[u8], path: &std::path::Path) -> String {
    let by_magic = detect_by_magic(data);

    if by_magic != "Unknown" {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext = ext.to_lowercase();
            match by_magic.as_str() {
                "PE (Windows Executable)" => {
                    return match ext.as_str() {
                        "dll" => "PE — DLL (Dynamic Library)".to_string(),
                        "sys" => "PE — Kernel Driver (.sys)".to_string(),
                        "scr" => "PE — Screensaver (.scr)".to_string(),
                        "ocx" => "PE — ActiveX Control (.ocx)".to_string(),
                        "cpl" => "PE — Control Panel (.cpl)".to_string(),
                        "drv" => "PE — Driver (.drv)".to_string(),
                        "efi" => "PE — EFI Executable".to_string(),
                        _ => by_magic,
                    };
                }
                "ZIP / JAR / APK / DOCX" => {
                    return match ext.as_str() {
                        "jar" => "JAR (Java Archive)".to_string(),
                        "apk" => "APK (Android Package)".to_string(),
                        "docx" => "DOCX (Word Document)".to_string(),
                        "xlsx" => "XLSX (Excel Spreadsheet)".to_string(),
                        "pptx" => "PPTX (PowerPoint)".to_string(),
                        "msix" => "MSIX (Windows Package)".to_string(),
                        "appx" => "AppX (Windows Package)".to_string(),
                        "epub" => "EPUB (eBook)".to_string(),
                        "zip" => "ZIP Archive".to_string(),
                        _ => by_magic,
                    };
                }
                "MS Office (DOC / XLS / PPT)" => {
                    return match ext.as_str() {
                        "doc" => "DOC (Word Document)".to_string(),
                        "xls" => "XLS (Excel Spreadsheet)".to_string(),
                        "ppt" => "PPT (PowerPoint)".to_string(),
                        "msi" => "MSI (Windows Installer)".to_string(),
                        "msg" => "MSG (Outlook Email)".to_string(),
                        _ => by_magic,
                    };
                }
                _ => return by_magic,
            }
        }
        return by_magic;
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return match ext.to_lowercase().as_str() {
            // Windows scripts
            "bat" | "cmd" => "Batch Script".to_string(),
            "ps1" => "PowerShell Script".to_string(),
            "vbs" => "VBScript".to_string(),
            "js" => "JavaScript".to_string(),
            "wsf" => "Windows Script File".to_string(),
            "hta" => "HTML Application".to_string(),

            // Unix scripts
            "sh" => "Shell Script".to_string(),
            "py" => "Python Script".to_string(),
            "rb" => "Ruby Script".to_string(),
            "pl" => "Perl Script".to_string(),
            "php" => "PHP Script".to_string(),
            "lua" => "Lua Script".to_string(),

            // Config / data
            "json" => "JSON".to_string(),
            "xml" => "XML".to_string(),
            "yaml" | "yml" => "YAML".to_string(),
            "toml" => "TOML".to_string(),
            "ini" | "cfg" => "Config File".to_string(),
            "csv" => "CSV (Spreadsheet)".to_string(),

            // Source code
            "rs" => "Rust Source".to_string(),
            "c" | "h" => "C Source".to_string(),
            "cpp" | "cc" => "C++ Source".to_string(),
            "go" => "Go Source".to_string(),
            "cs" => "C# Source".to_string(),

            _ => "Unknown".to_string(),
        };
    }

    "Unknown".to_string()
}

fn detect_by_magic(data: &[u8]) -> String {
    if data.len() < 4 {
        return "Unknown (too small)".to_string();
    }
    // MP4 / MOV Video check (ftyp starts at offset 4)
    if data.len() >= 8 && &data[4..8] == b"ftyp" {
        return "MP4 / MOV Video".to_string();
    }

    match &data[..4] {
        // Executables
        [0x7F, 0x45, 0x4C, 0x46] => "ELF (Linux/Unix)".to_string(),
        [0x4D, 0x5A, ..] => "PE (Windows Executable)".to_string(),
        [0xCE, 0xFA, 0xED, 0xFE]
        | [0xCF, 0xFA, 0xED, 0xFE]
        | [0xFE, 0xED, 0xFA, 0xCE]
        | [0xFE, 0xED, 0xFA, 0xCF] => "Mach-O (macOS)".to_string(),

        [0xCA, 0xFE, 0xBA, 0xBE] => {
            if data.len() >= 8 {
                let nfat = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                if (1..=10).contains(&nfat) {
                    "Mach-O Fat Binary".to_string()
                } else {
                    "Java .class".to_string()
                }
            } else {
                "Java .class".to_string()
            }
        }
        [0xBE, 0xBA, 0xFE, 0xCA] => "Mach-O Fat Binary".to_string(),
        [0x00, 0x61, 0x73, 0x6D] => "WebAssembly (.wasm)".to_string(),

        // Installers
        [0x4E, 0x53, 0x49, 0x53] => "NSIS Installer".to_string(),
        [0x49, 0x53, 0x63, 0x28] => "InstallShield Setup".to_string(),
        [0x4E, 0x45, 0x54, 0x20] => ".NET Native / ReadyToRun".to_string(),

        // Archives
        [0x50, 0x4B, 0x03, 0x04] => "ZIP / JAR / APK / DOCX".to_string(),
        [0x52, 0x61, 0x72, 0x21] => "RAR Archive".to_string(),
        [0x1F, 0x8B, ..] => "GZIP".to_string(),
        [0x42, 0x5A, 0x68, ..] => "BZIP2".to_string(),
        [0xFD, 0x37, 0x7A, 0x58] => "XZ Archive".to_string(),
        [0x37, 0x7A, 0xBC, 0xAF] => "7-Zip Archive".to_string(),
        [0x1F, 0x9D, ..] => "LZW (compressed)".to_string(),

        // Images
        [0xFF, 0xD8, 0xFF, ..] => "JPEG Image".to_string(),
        [0x89, 0x50, 0x4E, 0x47] => "PNG Image".to_string(),
        [0x47, 0x49, 0x46, 0x38] => "GIF Image".to_string(),
        [0x42, 0x4D, ..] => "BMP Image".to_string(),
        [0x49, 0x49, 0x2A, 0x00] | [0x4D, 0x4D, 0x00, 0x2A] => "TIFF Image".to_string(),

        // Documents
        [0x25, 0x50, 0x44, 0x46] => "PDF Document".to_string(),
        [0x7B, 0x5C, 0x72, 0x74] => "RTF Document".to_string(),
        [0xD0, 0xCF, 0x11, 0xE0] => "MS Office (DOC / XLS / PPT)".to_string(),

        // Audio
        [0x49, 0x44, 0x33, ..] => "MP3 Audio".to_string(),
        [0x4F, 0x67, 0x67, 0x53] => "OGG Audio".to_string(),
        [0x66, 0x4C, 0x61, 0x43] => "FLAC Audio".to_string(),
        [0x52, 0x49, 0x46, 0x46] => {
            if data.len() >= 12 {
                match &data[8..12] {
                    b"WAVE" => "WAV Audio".to_string(),
                    b"AVI " => "AVI Video".to_string(),
                    b"WEBP" => "WebP Image".to_string(),
                    b"ACON" => "ANI Cursor".to_string(),
                    _ => "RIFF Container".to_string(),
                }
            } else {
                "RIFF Container".to_string()
            }
        }
        // Video

        // System / Windows
        [0x4C, 0x00, 0x00, 0x00] => "Windows Shortcut (.lnk)".to_string(),
        [0x4D, 0x53, 0x43, 0x46] => "Windows Cabinet (.cab)".to_string(),
        [0x52, 0x45, 0x47, 0x46] => "Windows Registry Hive".to_string(),
        [0x4D, 0x44, 0x4D, 0x50] => "Windows Minidump (.dmp)".to_string(),

        // Databases
        [0x53, 0x51, 0x4C, 0x69] => "SQLite Database".to_string(),
        [0x57, 0x61, 0x6C, 0x00] => "SQLite WAL".to_string(),
        [0x4D, 0x44, 0x42, 0x00] => "MongoDB BSON".to_string(),
        [0x50, 0x47, 0x44, 0x4D] => "PostgreSQL (pgdump)".to_string(),

        // Fonts
        [0x00, 0x01, 0x00, 0x00] => "TrueType Font (.ttf)".to_string(),
        [0x4F, 0x54, 0x54, 0x4F] => "OpenType Font (.otf)".to_string(),
        [0x77, 0x4F, 0x46, 0x46] => "WOFF Font".to_string(),
        [0x77, 0x4F, 0x46, 0x32] => "WOFF2 Font".to_string(),

        // Disk images
        [0x43, 0x44, 0x30, 0x30] => "ISO Disk Image".to_string(),

        // Certificates / crypto
        [0x30, 0x82, ..] => "DER Certificate / Key".to_string(),
        [0x2D, 0x2D, 0x2D, 0x2D] => "PEM Certificate".to_string(),

        // Android
        [0x64, 0x65, 0x78, 0x0A] => "Android DEX".to_string(),

        // Scripts / text
        [0x23, 0x21, ..] => "Script (shebang)".to_string(),
        [0xEF, 0xBB, 0xBF, ..] => "UTF-8 Text (with BOM)".to_string(),
        [0xFF, 0xFE, ..] => "UTF-16 LE Text".to_string(),
        [0xFE, 0xFF, ..] => "UTF-16 BE Text".to_string(),

        _ => "Unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn detect(data: &[u8], name: &str) -> String {
        detect_with_path(data, Path::new(name))
    }

    #[test]
    fn elf_magic() {
        let mut d = vec![0x7F, 0x45, 0x4C, 0x46];
        d.extend_from_slice(&[0u8; 60]);
        assert_eq!(detect(&d, "binary"), "ELF (Linux/Unix)");
    }

    #[test]
    fn pe_exe() {
        let mut d = vec![0x4D, 0x5A];
        d.extend_from_slice(&[0u8; 60]);
        assert_eq!(detect(&d, "prog.exe"), "PE (Windows Executable)");
    }

    #[test]
    fn pe_dll_by_extension() {
        let mut d = vec![0x4D, 0x5A];
        d.extend_from_slice(&[0u8; 60]);
        assert_eq!(detect(&d, "lib.dll"), "PE — DLL (Dynamic Library)");
    }

    #[test]
    fn zip_by_magic() {
        let d = vec![0x50, 0x4B, 0x03, 0x04, 0u8, 0u8];
        assert_eq!(detect(&d, "archive.zip"), "ZIP Archive");
    }

    #[test]
    fn jar_by_extension() {
        let d = vec![0x50, 0x4B, 0x03, 0x04, 0u8, 0u8];
        assert_eq!(detect(&d, "app.jar"), "JAR (Java Archive)");
    }

    #[test]
    fn pdf_magic() {
        let d = b"%PDF-1.4 fake";
        assert_eq!(detect(d, "doc.pdf"), "PDF Document");
    }

    #[test]
    fn sqlite_magic() {
        let d = b"SQLite format 3\x00";
        assert_eq!(detect(d, "db.sqlite"), "SQLite Database");
    }

    #[test]
    fn png_magic() {
        let d = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect(&d, "img.png"), "PNG Image");
    }

    #[test]
    fn too_small_is_unknown() {
        assert!(detect(&[0x4D], "x").contains("Unknown"));
    }

    #[test]
    fn unknown_ext_fallback() {
        // no extension -> Unknown
        let d = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(detect(&d, "noextension"), "Unknown");

        // extension fallback when magic unknown
        let empty_magic = vec![0x00u8; 10];
        assert_eq!(detect(&empty_magic, "script.py"), "Python Script");
        assert_eq!(detect(&empty_magic, "config.toml"), "TOML");
    }
}
