use goblin::mach::{Mach, cputype};

use crate::{
    analysis::disasm::Arch,
    formats::{
        ParseResult,
        util::{checked_slice, is_new_best},
    },
};

fn macho_arch(cputype: u32) -> Arch {
    match cputype {
        cputype::CPU_TYPE_X86_64 => Arch::X86_64,
        cputype::CPU_TYPE_X86 => Arch::X86,
        cputype::CPU_TYPE_ARM64 => Arch::Arm64,
        cputype::CPU_TYPE_ARM => Arch::Arm,
        _ => Arch::Unknown,
    }
}

pub fn macho_parse_all(data: &[u8]) -> ParseResult {
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
                    let name = section.name().unwrap_or("<unreadable name>");
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

            let mut text_section: Option<(Vec<u8>, u64, Arch)> = None;
            let mut text_matches = 0usize;
            for segment in &macho.segments {
                for (section, _) in &segment.sections().unwrap_or_default() {
                    if let Ok(name) = section.name()
                        && name == "__text"
                    {
                        text_matches += 1;
                        let offset = section.offset as usize;
                        let size = section.size as usize;
                        if let Some(bytes) = checked_slice(data, offset, size) {
                            let current_best = text_section.as_ref().map(|(b, _, _)| b.len());
                            if is_new_best(current_best, bytes.len()) {
                                let arch = macho_arch(macho.header.cputype);
                                text_section = Some((bytes, section.addr, arch));
                            }
                        }
                    }
                }
            }
            if text_matches > 1 {
                sections.push(String::new());
                sections.push(format!(
                    "  Note: {} sections named \"__text\" found; using the largest",
                    text_matches
                ));
            }

            (sections, imports, text_section)
        }
        Ok(Mach::Fat(fat)) => {
            let arches = fat.arches().unwrap_or_default();
            let mut sections = vec![
                "  Format       : Mach-O Fat Binary".to_string(),
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
                None,
            )
        }
        Err(e) => (
            vec![format!("  Parse error: {}", e)],
            vec![format!("  Parse error: {}", e)],
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_data_does_not_panic() {
        let r = macho_parse_all(b"garbage not a real macho binary");
        assert!(!r.0.is_empty());
    }

    #[test]
    fn arch_mapping_known_types() {
        assert_eq!(macho_arch(cputype::CPU_TYPE_X86_64), Arch::X86_64);
        assert_eq!(macho_arch(cputype::CPU_TYPE_X86), Arch::X86);
        assert_eq!(macho_arch(cputype::CPU_TYPE_ARM64), Arch::Arm64);
        assert_eq!(macho_arch(cputype::CPU_TYPE_ARM), Arch::Arm);
    }

    #[test]
    fn arch_mapping_unknown_type_is_unknown() {
        assert_eq!(macho_arch(0xDEAD), Arch::Unknown);
    }
}
