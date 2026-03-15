# Binpeek

A fast, terminal-based binary file inspector with a TUI interface.

Supports **PE** (Windows `.exe` / `.dll`), **ELF** (Linux), and **Mach-O** (macOS) formats.

![binpeek demo](https://raw.githubusercontent.com/Kleshzz/binpeek/main/assets/demo.png)

## Features

- **Overview** — file size, format detection, entropy analysis
- **Sections** — virtual addresses, sizes, entry point, image base
- **Imports** — imported DLLs and functions (PE) / libraries and symbols (ELF)
- **Strings** — extracted printable strings from the binary
- Fast and lightweight — no runtime dependencies, single binary

## Installation

### From source

```bash
git clone https://github.com/Kleshzz/binpeek
cd binpeek
cargo build --release
```

Binary will be at `target/release/binpeek` (or `binpeek.exe` on Windows).

### Via cargo

```bash
cargo install binpeek
```

## Usage

```bash
binpeek <file>
```

**Examples:**

```bash
# Inspect a Windows executable
binpeek notepad.exe

# Inspect a Linux binary
binpeek /usr/bin/ls

# Inspect a DLL
binpeek kernel32.dll
```

## Controls

| Key | Action |
|-----|--------|
| `1` `2` `3` `4` | Switch tabs |
| `↑` `↓` | Scroll line |
| `PgUp` `PgDn` | Scroll page |
| `Home` | Scroll to top |
| `q` | Quit |

## Tabs

| Tab | Description |
|-----|-------------|
| **Overview** | File info, format, entropy |
| **Sections** | Binary sections with addresses and sizes |
| **Imports** | Imported libraries and functions |
| **Strings** | Extracted ASCII strings (min. 5 chars) |

## Entropy guide

| Range | Meaning |
|-------|---------|
| 0 – 2 | Plain text / very low |
| 3 – 5 | Normal binary |
| 6 – 7 | Compressed or encrypted |
| 7 – 8 | Likely packed / encrypted |

## Supported formats

| Format | Platform | Sections | Imports |
|--------|----------|----------|---------|
| PE (`.exe`, `.dll`) | Windows | ✅ | ✅ |
| ELF | Linux / Unix | ✅ | ✅ |
| Mach-O | macOS | 🔜 | 🔜 |

## License

MIT
