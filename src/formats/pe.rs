use goblin::pe::PE;

pub fn pe_parse_all(data: &[u8]) -> (Vec<String>, Vec<String>) {
    match PE::parse(data) {
        Ok(pe) => {
            // Sections
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

            // Imports
            let mut imports = vec![];
            let mut current_dll = String::new();
            for import in &pe.imports {
                if import.dll != current_dll {
                    if !current_dll.is_empty() { imports.push(String::new()); }
                    imports.push(format!("  [{}]", import.dll));
                    current_dll = import.dll.to_string();
                }
                imports.push(format!("    {}", import.name));
            }

            (sections, imports)
        }
        Err(e) => (
            vec![format!("Parse error: {}", e)],
            vec![format!("Parse error: {}", e)],
        ),
    }
}
