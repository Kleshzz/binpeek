use goblin::elf::Elf;

pub fn elf_parse_all(data: &[u8]) -> (Vec<String>, Vec<String>) {
    match Elf::parse(data) {
        Ok(elf) => {
            // Sections
            let mut sections = vec![
                format!("  Architecture : {}", if elf.is_64 { "64-bit" } else { "32-bit" }),
                format!("  Little endian: {}", elf.little_endian),
                format!("  Entry point  : 0x{:X}", elf.entry),
                String::new(),
                format!("  {:20}  {:>12}  {:>12}", "Name", "Offset", "Size"),
                format!("  {}", "-".repeat(50)),
            ];
            for section in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("?");
                sections.push(format!(
                    "  {:20}  0x{:08X}    {:>10} bytes",
                    name, section.sh_offset, section.sh_size
                ));
            }

            // Imports
            let mut imports = vec![];
            if !elf.libraries.is_empty() {
                imports.push("  [Libraries]".to_string());
                for lib in &elf.libraries {
                    imports.push(format!("    {}", lib));
                }
                imports.push(String::new());
            }
            imports.push("  [Symbols]".to_string());
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        imports.push(format!("    0x{:08X}  {}", sym.st_value, name));
                    }
                }
            }

            (sections, imports)
        }
        Err(e) => (
            vec![format!("Parse error: {}", e)],
            vec![format!("Parse error: {}", e)],
        ),
    }
}
