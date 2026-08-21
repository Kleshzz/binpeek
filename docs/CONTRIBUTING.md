# Contributing to binpeek 🔍

First of all, thank you for considering contributing to `binpeek`! Any help, whether it's reporting bugs, suggesting features, or adding new file signatures, is greatly appreciated.

## How to add a new signature?

Most of the logic for detecting file formats, languages, and packers is located in `src/analysis/`:

- **File Formats**: Handled in `src/analysis/detector.rs` via magic bytes or file extensions.
- **Languages, Packers, and Obfuscators**: Handled in `src/analysis/lang.rs` via string matching in the binary data.

### Example: Adding a new Obfuscator detection

1. Find a unique string or byte pattern in the target binary (e.g., using `strings`).
2. Add a check in the `detect_obfuscator` function in `src/analysis/lang.rs`:
   ```rust
   if text.contains("UniqueMarker") {
       return Some("MyCoolObfuscator");
   }
   ```
3. Run `cargo check` to ensure the project still compiles.

## Pull Request Process

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'Add some amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

## Requirements

- **Code Formatting**: Please run `cargo fmt` before committing.
- **Build Status**: Ensure the project builds successfully with `cargo build`.
- **Documentation**: If you're adding a major new feature, please update the README accordingly.

Thank you for making `binpeek` better!
