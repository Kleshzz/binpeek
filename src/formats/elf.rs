use goblin::elf::Elf;

pub fn elf_sections_str(data: &[u8]) -> Vec<String> {
    match Elf::parse(data) {
        Ok(elf) => {
            let mut lines = vec![
                format!("  Architecture : {}", if elf.is_64 { "64-bit" } else { "32-bit" }),
                format!("  Little endian: {}", elf.little_endian),
                format!("  Entry point  : 0x{:X}", elf.entry),
                String::new(),
                format!("  {:20}  {:>12}  {:>12}", "Name", "Offset", "Size"),
                format!("  {}", "-".repeat(50)),
            ];
            for section in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("?");
                lines.push(format!(
                    "  {:20}  0x{:08X}    {:>10} bytes",
                    name, section.sh_offset, section.sh_size
                ));
            }
            lines
        }
        Err(e) => vec![format!("Parse error: {}", e)],
    }
}

pub fn elf_imports_str(data: &[u8]) -> Vec<String> {
    match Elf::parse(data) {
        Ok(elf) => {
            let mut lines = vec![];
            if !elf.libraries.is_empty() {
                lines.push("  [Libraries]".to_string());
                for lib in &elf.libraries {
                    lines.push(format!("    {}", lib));
                }
                lines.push(String::new());
            }
            lines.push("  [Symbols]".to_string());
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        lines.push(format!("    0x{:08X}  {}", sym.st_value, name));
                    }
                }
            }
            lines
        }
        Err(e) => vec![format!("Parse error: {}", e)],
    }
}
