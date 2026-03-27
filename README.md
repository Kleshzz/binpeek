# binpeek

A fast, terminal-based binary file inspector with a TUI interface.

Supports **PE** (Windows `.exe` / `.dll`), **ELF** (Linux), **Mach-O** (macOS) and [40+ other formats](#supported-formats).

![binpeek demo](https://raw.githubusercontent.com/Kleshzz/binpeek/main/assets/demo.png)

## Features

- **Overview** — file size, format detection, entropy, language, packer and obfuscator detection
- **Sections** — virtual addresses, sizes, entry point, image base
- **Imports** — imported DLLs and functions (PE) / libraries and symbols (ELF)
- **Strings** — extracted printable ASCII strings (min. 5 chars, up to 10 000)
- **Disasm** — disassembly of the `.text` section via Capstone (x86/x64)
- Fast and lightweight — single binary, no runtime dependencies

## Installation

### Download binary (recommended)

Grab the latest release for your platform from the [Releases](https://github.com/Kleshzz/binpeek/releases) page:

| Platform | File |
|----------|------|
| Windows x64 | `binpeek-windows-x64.exe` |
| Windows x86 | `binpeek-windows-x86.exe` |
| Windows ARM64 | `binpeek-windows-arm64.exe` |
| Linux x64 | `binpeek-linux-x64` |
| Linux ARM64 | `binpeek-linux-arm64` |
| macOS Intel | `binpeek-macos-x64` |
| macOS Apple Silicon | `binpeek-macos-arm64` |

### Via cargo

```bash
cargo install binpeek
```

### From source

```bash
git clone https://github.com/Kleshzz/binpeek
cd binpeek
cargo build --release
```

Binary will be at `target/release/binpeek` (or `binpeek.exe` on Windows).

## Usage

```bash
binpeek <file-path>
```

**Examples:**

```bash
# Inspect a Windows executable
binpeek C:\Windows\System32\notepad.exe

# Inspect a DLL
binpeek C:\Windows\System32\kernel32.dll

# Inspect a Linux binary
binpeek /usr/bin/ls

# Inspect any file — images, archives, documents
binpeek suspicious.pdf
binpeek archive.zip
```

> **Tip:** If a file is packed with UPX, binpeek will detect it and suggest unpacking first:
> ```
> Packer: UPX ⚠ unpack first: upx -d <file-path>
> ```

## Controls

| Key | Action |
|-----|--------|
| `1` `2` `3` `4` `5` | Switch tabs |
| `↑` `↓` | Scroll one line |
| `PgUp` `PgDn` | Scroll one page |
| `Home` | Scroll to top |
| `q` | Quit |

## Tabs

| # | Tab | Description |
|---|-----|-------------|
| 1 | **Overview** | File info, format, entropy, language, packer, obfuscator |
| 2 | **Sections** | Binary sections with virtual addresses and sizes |
| 3 | **Imports** | Imported libraries and functions |
| 4 | **Strings** | Extracted ASCII strings |
| 5 | **Disasm** | Disassembly of `.text` section (x86/x64) |

## Language & packer detection

binpeek automatically detects:

**Languages:** Go, Rust, .NET / C#, Python, Zig, Nim, Haskell, D, Crystal, Swift, Delphi / Pascal, AutoIt, VB6, C / C++ (MSVC / GCC / Clang), Ada, Fortran, Ruby, Lua.

**Frameworks:** Electron (Node.js), Flutter (Dart), Unity (C#).

**Packers:** UPX, MPRESS, NSPack, PECompact, ASPack, FSG, Themida, VMProtect, Enigma Virtual Box, MoleBox, Petite, PESpin, BoxedApp SDK.

**Obfuscators:** Garble (Go), Nuitka, PyInstaller, ConfuserEx, Babel.NET, .NET Reactor, Eazfuscator, Skater, SmartAssembly, Dotfuscator, Xenocode, Spices.Net, Enigma Protector, Obsidium, PyArmor.

## Contributing

Contributions are welcome! Whether it's a bug fix, a new feature, or just a new file signature. 

Check out [CONTRIBUTING.md](./CONTRIBUTING.md) to get started!

## Entropy guide

| Range | Meaning |
|-------|---------|
| 0 – 2 | Plain text / very low |
| 3 – 5 | Normal binary |
| 6 – 7 | Compressed or encrypted |
| 7 – 8 | Likely packed / encrypted |

## Supported formats

**Executables:** PE (.exe, .dll), ELF, Mach-O, Java .class, WebAssembly

**Archives:** ZIP / JAR / APK, RAR, GZIP, BZIP2, XZ, 7-Zip, TAR

**Images:** JPEG, PNG, GIF, BMP, TIFF, WebP

**Documents:** PDF, RTF, MS Office (DOC/XLS/PPT)

**Audio:** MP3, OGG, FLAC, WAV

**Video:** MP4 / MOV

**System:** Windows Shortcut (.lnk), Cabinet (.cab), Registry Hive, Minidump, SQLite

## Credits

`binpeek` wouldn't be possible without these amazing crates:

- [ratatui](https://github.com/ratatui/ratatui) — terminal user interface
- [capstone-rs](https://github.com/capstone-rust/capstone-rs) — disassembly engine
- [goblin](https://github.com/m4b/goblin) — binary format parsing
- [crossterm](https://github.com/crossterm-rs/crossterm) — cross-platform terminal manipulation
- [clap](https://github.com/clap-rs/clap) — command line argument parsing

## License

MIT
