use goblin::elf::Elf;

pub fn elf_parse_all(data: &[u8]) -> (Vec<String>, Vec<String>) {
    match Elf::parse(data) {
        Ok(elf) => {
            let mut sections = vec![
                format!(
                    "  Architecture : {}",
                    if elf.is_64 { "64-bit" } else { "32-bit" }
                ),
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
                if let Some(name) = elf.strtab.get_at(sym.st_name)
                    && !name.is_empty()
                {
                    imports.push(format!("    0x{:08X}  {}", sym.st_value, name));
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

pub fn elf_text_section(data: &[u8]) -> Option<(Vec<u8>, u64, bool)> {
    match Elf::parse(data) {
        Ok(elf) => {
            for section in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
                if name == ".text" {
                    let offset = section.sh_offset as usize;
                    let size = section.sh_size as usize;
                    if offset + size <= data.len() {
                        let bytes = data[offset..offset + size].to_vec();
                        return Some((bytes, section.sh_addr, elf.is_64));
                    }
                }
            }
            None
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_data_does_not_panic() {
        let r = elf_parse_all(b"\x7FELF garbage not a real elf binary here");
        assert!(!r.0.is_empty());
    }

    #[test]
    fn text_section_on_garbage_returns_none() {
        assert!(elf_text_section(b"\x7FELF garbage").is_none());
    }
}
