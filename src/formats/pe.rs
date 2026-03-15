use goblin::pe::PE;

pub fn pe_sections_str(data: &[u8]) -> Vec<String> {
    match PE::parse(data) {
        Ok(pe) => {
            let mut lines = vec![
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
                lines.push(format!(
                    "  {:10}  0x{:08X}    {:>10} bytes",
                    name, s.virtual_address, s.size_of_raw_data
                ));
            }
            lines
        }
        Err(e) => vec![format!("Parse error: {}", e)],
    }
}

pub fn pe_imports_str(data: &[u8]) -> Vec<String> {
    match PE::parse(data) {
        Ok(pe) => {
            let mut lines = vec![];
            let mut current_dll = String::new();
            for import in &pe.imports {
                if import.dll != current_dll {
                    if !current_dll.is_empty() {
                        lines.push(String::new());
                    }
                    lines.push(format!("  [{}]", import.dll));
                    current_dll = import.dll.to_string();
                }
                lines.push(format!("    {}", import.name));
            }
            lines
        }
        Err(e) => vec![format!("Parse error: {}", e)],
    }
}
