use goblin::pe::PE;

pub fn pe_parse_all(data: &[u8]) -> (Vec<String>, Vec<String>) {
    match PE::parse(data) {
        Ok(pe) => {
            let mut sections = vec![
                format!("  Entry point : 0x{:X}", pe.entry),
                format!("  Image base  : 0x{:X}", pe.image_base),
                format!("  64-bit      : {}", pe.is_64),
                format!("  DLL         : {}", pe.is_lib),
                String::new(),
                format!("  {:10}  {:>12}  {:>12}", "Name", "Virt. Addr.", "Size"),
                format!("  {}", "-".repeat(40)),
            ];
            for s in &pe.sections {
                let name = std::str::from_utf8(&s.name)
                    .unwrap_or("?")
                    .trim_matches('\0')
                    .to_string();
                sections.push(format!(
                    "  {:10}  0x{:08X}    {:>10} bytes",
                    name, s.virtual_address, s.size_of_raw_data
                ));
            }

            let mut imports = vec![];
            let mut current_dll = String::new();
            for import in &pe.imports {
                if import.dll != current_dll {
                    if !current_dll.is_empty() {
                        imports.push(String::new());
                    }
                    imports.push(format!("  [{}]", import.dll));
                    current_dll = import.dll.to_string();
                }
                imports.push(format!("    {}", import.name));
            }

            (sections, imports)
        }
        Err(e) => {
            let msg = e.to_string();
            let sections = vec![
                "  Warning: PE parse error (malformed or packed binary)".to_string(),
                format!("  Details: {}", msg),
                String::new(),
                "  Basic info may be unavailable. Try unpacking first (upx -d <file>).".to_string(),
            ];
            (
                sections,
                vec!["  Import table unavailable due to parse error.".to_string()],
            )
        }
    }
}

pub fn pe_text_section(data: &[u8]) -> Option<(Vec<u8>, u64, bool)> {
    match PE::parse(data) {
        Ok(pe) => {
            for section in &pe.sections {
                let name = std::str::from_utf8(&section.name)
                    .unwrap_or("")
                    .trim_matches('\0');
                if name == ".text" {
                    let offset = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    if offset + size <= data.len() {
                        let bytes = data[offset..offset + size].to_vec();
                        let va = pe.image_base + section.virtual_address as u64;
                        return Some((bytes, va, pe.is_64));
                    }
                }
            }
            None
        }
        Err(_) => None,
    }
}
