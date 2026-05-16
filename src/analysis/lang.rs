pub struct FileInfo {
    pub language: &'static str,
    pub packer: Option<&'static str>,
    pub obfuscator: Option<&'static str>,
}

pub fn detect(data: &[u8]) -> FileInfo {
    // Binary magic-checks before lossy conversion
    if data.len() >= 8 && data[..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
        let nfat = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if nfat > 10 {
            // This is Java .class, not a Mach-O fat binary
            return FileInfo {
                language: "Java",
                packer: None,
                obfuscator: None,
            };
        }
    }

    let data = &data[..data.len().min(2_000_000)];
    let text = String::from_utf8_lossy(data);
    let packer = detect_packer(&text);
    let obfuscator = detect_obfuscator(&text);
    let language = detect_language(&text);

    FileInfo {
        language,
        packer,
        obfuscator,
    }
}

fn detect_packer(text: &str) -> Option<&'static str> {
    if text.contains("UPX0") || text.contains("UPX1") || text.contains("UPX!") {
        return Some("UPX");
    }
    if text.contains("MPRESS1") || text.contains("MPRESS2") {
        return Some("MPRESS");
    }
    if text.contains(".nsp0") || text.contains(".nsp1") {
        return Some("NSPack");
    }
    if text.contains("PECompact2") {
        return Some("PECompact");
    }
    if text.contains("ASPack") {
        return Some("ASPack");
    }
    if text.contains("FSG!") {
        return Some("FSG");
    }
    if text.contains("PEC2") {
        return Some("PECrypt32");
    }
    if text.contains("Themida") {
        return Some("Themida");
    }
    if text.contains("VMProtect") {
        return Some("VMProtect");
    }
    if text.contains("Enigma Virtual Box") {
        return Some("Enigma Virtual Box");
    }
    if text.contains(".petite") || text.contains("Petite") {
        return Some("Petite");
    }
    if text.contains("PESpin") {
        return Some("PESpin");
    }
    if text.contains("MoleBox") {
        return Some("MoleBox");
    }
    if text.contains("BoxedApp") {
        return Some("BoxedApp SDK");
    }
    None
}

fn detect_obfuscator(text: &str) -> Option<&'static str> {
    let has_go_runtime = text.contains("runtime.") && text.contains("goroutine");
    let has_build_id = text.contains("Go build ID") || text.contains("go:buildid");
    let has_go_symbols = text.contains("main.main") || text.contains("main.init");

    if has_go_runtime && !has_build_id && !has_go_symbols {
        return Some("Garble (Go obfuscator)");
    }

    if text.contains("ConfuserEx") || text.contains("Confuser") {
        return Some("ConfuserEx (.NET)");
    }
    if text.contains("de4dot") {
        return Some("de4dot (.NET)");
    }
    if text.contains(".NET Reactor") {
        return Some(".NET Reactor");
    }
    if text.contains("Eazfuscator") {
        return Some("Eazfuscator (.NET)");
    }
    if text.contains("SmartAssembly") {
        return Some("SmartAssembly (.NET)");
    }
    if text.contains("Dotfuscator") {
        return Some("Dotfuscator (.NET)");
    }
    if text.contains("BabelAttribute") || text.contains("Babel.Net") {
        return Some("Babel.NET (.NET)");
    }
    if text.contains("Skater") {
        return Some("Skater (.NET)");
    }
    if text.contains("Xenocode") {
        return Some("Xenocode (.NET)");
    }
    if text.contains("Spices.Net") {
        return Some("Spices.Net (.NET)");
    }
    if text.contains("Enigma Protector") {
        return Some("Enigma Protector");
    }
    if text.contains("Obsidium") {
        return Some("Obsidium");
    }
    if text.contains("PyArmor") {
        return Some("Python (PyArmor protected)");
    }
    if text.contains("__nuitka") || text.contains("nuitka") {
        return Some("Nuitka (Compiler/Obfuscator)");
    }
    if text.contains(".pydata") || text.contains("PyInstaller") {
        return Some("PyInstaller (Packer)");
    }
    None
}

fn detect_language(text: &str) -> &'static str {
    // Go
    if text.contains("Go build ID")
        || text.contains("go:buildid")
        || text.contains("runtime.gopanic")
        || text.contains("goroutine ")
    {
        return "Go";
    }

    // Rust
    if text.contains("rustc") || text.contains("core::panicking") {
        return "Rust";
    }
    if text.contains("rust_begin_unwind") || text.contains("__rust_") {
        return "Rust";
    }

    // .NET / C#
    if text.contains("_CorExeMain") || text.contains("mscoree.dll") {
        return ".NET / C#";
    }
    if text.contains("mscorlib") {
        return ".NET / C#";
    }

    // Swift
    if text.contains("_swift_") || text.contains("SwiftObject") {
        return "Swift";
    }

    // Python
    if text.contains("__nuitka")
        || text.contains("nuitka")
        || text.contains("python3")
        || text.contains("Python 3")
        || text.contains(".pydata")
        || text.contains("PyInstaller")
        || text.contains("Py_InitializeEx")
    {
        return "Python";
    }

    // Electron
    if text.contains("app.asar") || text.contains("electron") {
        return "Electron (Node.js)";
    }

    // Delphi / Pascal
    if text.contains("Borland") || text.contains("Delphi") {
        return "Delphi / Pascal";
    }
    if text.contains("TApplication") {
        return "Delphi";
    }

    // AutoIt
    if text.contains("AutoIt") || text.contains(">AUTOIT") {
        return "AutoIt";
    }

    // VB6
    if text.contains("VB5!") || text.contains("VB6!") || text.contains("MSVBVM60") {
        return "Visual Basic 6";
    }

    // C++ (MSVC)
    if text.contains("MSVCP") || text.contains("VCRUNTIME") {
        return "C++ (MSVC)";
    }
    if text.contains("libstdc++") || text.contains("libgcc") {
        return "C++ (GCC/MinGW)";
    }

    // Zig
    if text.contains("zig_panic") || text.contains("__zig_") {
        return "Zig";
    }

    // Nim
    if text.contains("nim_panic") || text.contains("nim_program_result") {
        return "Nim";
    }

    // Haskell
    if text.contains("GHC.Base") || text.contains("ghc-prim") {
        return "Haskell (GHC)";
    }

    // D
    if text.contains("_Dmain") || text.contains("_Dmodule_ref") {
        return "D";
    }

    // Crystal
    if text.contains("__crystal_main") || text.contains("crystal_init") {
        return "Crystal";
    }

    // Ada
    if text.contains("__gnat_") {
        return "Ada (GNAT)";
    }

    // Fortran
    if text.contains("_gfortran_") {
        return "Fortran";
    }

    // Flutter / Dart
    if text.contains("libflutter.so") || text.contains("FlutterMain") {
        return "Dart (Flutter)";
    }

    // Unity
    if text.contains("UnityPlayer.dll") || text.contains("UnityMain") {
        return "C# (Unity Engine)";
    }

    // Ruby
    if text.contains("ruby_init") || text.contains("libruby") {
        return "Ruby (embedded)";
    }

    // Lua
    if text.contains("lua_newstate") || text.contains("luaL_newstate") {
        return "Lua (embedded)";
    }

    // C++ (Clang)
    if text.contains("clang") {
        return "C / C++ (Clang)";
    }

    "Unknown / C"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lang(snippet: &[u8]) -> &'static str {
        detect(snippet).language
    }

    fn packer(snippet: &[u8]) -> Option<&'static str> {
        detect(snippet).packer
    }

    fn obf(snippet: &[u8]) -> Option<&'static str> {
        detect(snippet).obfuscator
    }

    #[test]
    fn detects_go() {
        assert_eq!(lang(b"Go build ID: abc123"), "Go");
        assert_eq!(lang(b"goroutine 1 [running]"), "Go");
    }

    #[test]
    fn detects_rust() {
        assert_eq!(lang(b"rustc 1.75.0 core::panicking"), "Rust");
        assert_eq!(lang(b"rust_begin_unwind panic"), "Rust");
    }

    #[test]
    fn detects_dotnet() {
        assert_eq!(lang(b"_CorExeMain mscoree.dll"), ".NET / C#");
    }

    #[test]
    fn detects_python() {
        assert_eq!(lang(b"PyInstaller bundle"), "Python");
    }

    #[test]
    fn detects_upx() {
        assert_eq!(packer(b"UPX0\x00UPX1\x00UPX!"), Some("UPX"));
    }

    #[test]
    fn detects_vmprotect() {
        assert_eq!(packer(b"VMProtect section data"), Some("VMProtect"));
    }

    #[test]
    fn detects_confuserex() {
        assert_eq!(obf(b"ConfuserEx v1.0 protected"), Some("ConfuserEx (.NET)"));
    }

    #[test]
    fn unknown_is_fallback() {
        assert_eq!(lang(b"\x00\x01\x02\x03"), "Unknown / C");
        assert_eq!(packer(b"\x00\x01\x02\x03"), None);
        assert_eq!(obf(b"\x00\x01\x02\x03"), None);
    }

    #[test]
    fn java_class_magic() {
        // CAFEBABE with nfat > 10 -> Java
        let mut d = vec![0xCA, 0xFE, 0xBA, 0xBE];
        // nfat = 0xCAFE (>10) as big-endian u32
        d.extend_from_slice(&[0x00, 0x00, 0x00, 0x34]);
        assert_eq!(lang(&d), "Java");
    }
}
