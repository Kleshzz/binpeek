use goblin::mach::Mach;

pub fn macho_parse_all(data: &[u8]) -> (Vec<String>, Vec<String>) {
    match Mach::parse(data) {
        Ok(Mach::Binary(macho)) => {
            let mut sections = vec![
                format!(
                    "  Architecture : {}",
                    if macho.is_64 { "64-bit" } else { "32-bit" }
                ),
                format!("  CPU Type     : 0x{:X}", macho.header.cputype),
                format!("  File Type    : 0x{:X}", macho.header.filetype),
                String::new(),
                format!("  {:20}  {:>12}  {:>12}", "Section", "Offset", "Size"),
                format!("  {}", "-".repeat(50)),
            ];

            for segment in &macho.segments {
                for (section, _) in &segment.sections().unwrap_or_default() {
                    let name = section.name().unwrap_or("?");
                    sections.push(format!(
                        "  {:20}  0x{:08X}    {:>10} bytes",
                        name, section.offset, section.size
                    ));
                }
            }

            let mut imports = vec![];
            if !macho.libs.is_empty() {
                imports.push("  [Libraries]".to_string());
                for lib in &macho.libs {
                    imports.push(format!("    {}", lib));
                }
                imports.push(String::new());
            }

            imports.push("  [Exports]".to_string());
            if let Ok(exports) = macho.exports() {
                for export in exports {
                    imports.push(format!("    {}", export.name));
                }
            }

            imports.push(String::new());
            imports.push("  [Imports]".to_string());
            if let Ok(m_imports) = macho.imports() {
                for import in m_imports {
                    imports.push(format!("    {}  ({})", import.name, import.dylib));
                }
            }

            (sections, imports)
        }
        Ok(Mach::Fat(fat)) => {
            let arches = fat.arches().unwrap_or_default();
            let mut sections = vec![
                format!("  Format       : Mach-O Fat Binary"),
                format!("  Arches count : {}", arches.len()),
                String::new(),
            ];

            for arch in arches {
                sections.push(format!(
                    "  CPU: 0x{:08X}  Sub: 0x{:08X}  Offset: 0x{:08X}",
                    arch.cputype, arch.cpusubtype, arch.offset
                ));
            }

            (
                sections,
                vec!["  Imports not available for Fat Binary (choose architecture)".to_string()],
            )
        }
        Err(e) => (
            vec![format!("  Parse error: {}", e)],
            vec![format!("  Parse error: {}", e)],
        ),
    }
}

pub fn macho_text_section(data: &[u8]) -> Option<(Vec<u8>, u64, bool)> {
    match Mach::parse(data) {
        Ok(Mach::Binary(macho)) => {
            for segment in &macho.segments {
                for (section, _) in &segment.sections().unwrap_or_default() {
                    if let Ok(name) = section.name()
                        && name == "__text"
                    {
                        let offset = section.offset as usize;
                        let size = section.size as usize;
                        if offset + size <= data.len() {
                            let bytes = data[offset..offset + size].to_vec();
                            return Some((bytes, section.addr, macho.is_64));
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}
