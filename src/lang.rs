pub struct FileInfo {
    pub language: &'static str,
    pub packer:   Option<&'static str>,
    pub obfuscator: Option<&'static str>,
}

pub fn detect(data: &[u8]) -> FileInfo {
    let packer     = detect_packer(data);
    let obfuscator = detect_obfuscator(data);
    let language   = detect_language(data);

    FileInfo { language, packer, obfuscator }
}

fn contains(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len()).any(|w| w == pattern)
}

fn detect_packer(data: &[u8]) -> Option<&'static str> {
    if contains(data, b"UPX0") || contains(data, b"UPX1") || contains(data, b"UPX!") {
        return Some("UPX");
    }
    if contains(data, b"MPRESS1") || contains(data, b"MPRESS2") {
        return Some("MPRESS");
    }
    if contains(data, b".nsp0") || contains(data, b".nsp1") {
        return Some("NSPack");
    }
    if contains(data, b"PECompact2") {
        return Some("PECompact");
    }
    if contains(data, b"ASPack") {
        return Some("ASPack");
    }
    if contains(data, b"FSG!") {
        return Some("FSG");
    }
    if contains(data, b"PEC2") {
        return Some("PECrypt32");
    }
    if contains(data, b"Themida") {
        return Some("Themida");
    }
    if contains(data, b"VMProtect") {
        return Some("VMProtect");
    }
    None
}

fn detect_obfuscator(data: &[u8]) -> Option<&'static str> {
    let has_go_runtime = contains(data, b"runtime.") && contains(data, b"goroutine");
    let has_build_id   = contains(data, b"Go build ID") || contains(data, b"go:buildid");
    let has_go_symbols = contains(data, b"main.main") || contains(data, b"main.init");

    if has_go_runtime && !has_build_id && !has_go_symbols {
        return Some("Garble (Go obfuscator)");
    }

    if contains(data, b"ConfuserEx") || contains(data, b"Confuser") {
        return Some("ConfuserEx (.NET)");
    }
    if contains(data, b"de4dot") {
        return Some("de4dot (.NET)");
    }
    if contains(data, b".NET Reactor") {
        return Some(".NET Reactor");
    }
    if contains(data, b"Eazfuscator") {
        return Some("Eazfuscator (.NET)");
    }
    if contains(data, b"SmartAssembly") {
        return Some("SmartAssembly (.NET)");
    }
    if contains(data, b"Dotfuscator") {
        return Some("Dotfuscator (.NET)");
    }
    if contains(data, b"Enigma Protector") {
        return Some("Enigma Protector");
    }
    if contains(data, b"Obsidium") {
        return Some("Obsidium");
    }
    None
}

fn detect_language(data: &[u8]) -> &'static str {
    // Go
    if contains(data, b"Go build ID") || contains(data, b"go:buildid") {
        return "Go";
    }
    if contains(data, b"runtime.gopanic") || contains(data, b"goroutine ") {
        return "Go (obfuscated)";
    }

    // Rust
    if contains(data, b"rustc") || contains(data, b"core::panicking") {
        return "Rust";
    }
    if contains(data, b"rust_begin_unwind") || contains(data, b"__rust_") {
        return "Rust";
    }

    // .NET / C#
    if contains(data, b"_CorExeMain") || contains(data, b"mscoree.dll") {
        return ".NET / C#";
    }
    if contains(data, b"mscorlib") {
        return ".NET / C#";
    }

    // Python
    if contains(data, b"python3") || contains(data, b"Python 3") {
        return "Python";
    }
    if contains(data, b".pydata") || contains(data, b"PyInstaller") {
        return "Python (PyInstaller)";
    }
    if contains(data, b"Py_InitializeEx") {
        return "Python (embedded)";
    }

    // Delphi / Pascal
    if contains(data, b"Borland") || contains(data, b"Delphi") {
        return "Delphi / Pascal";
    }
    if contains(data, b"TApplication") {
        return "Delphi";
    }

    // AutoIt
    if contains(data, b"AutoIt") || contains(data, b">AUTOIT") {
        return "AutoIt";
    }

    // VB6
    if contains(data, b"VB5!") || contains(data, b"VB6!") || contains(data, b"MSVBVM60") {
        return "Visual Basic 6";
    }

    // C++ (MSVC)
    if contains(data, b"MSVCP") || contains(data, b"VCRUNTIME") {
        return "C++ (MSVC)";
    }
    if contains(data, b"libstdc++") || contains(data, b"libgcc") {
        return "C++ (GCC/MinGW)";
    }

    // C++ (Clang)
    if contains(data, b"clang") {
        return "C / C++ (Clang)";
    }

    // Java
    if data.len() >= 4 && &data[..4] == b"\xCA\xFE\xBA\xBE" {
        return "Java";
    }

    "Unknown / C"
}
