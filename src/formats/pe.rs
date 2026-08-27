use goblin::pe::{PE, header};

use crate::{
    analysis::disasm::Arch,
    formats::{
        ParseResult,
        util::{checked_slice, is_new_best},
    },
};

fn pe_arch(machine: u16) -> Arch {
    match machine {
        header::COFF_MACHINE_X86_64 => Arch::X86_64,
        header::COFF_MACHINE_X86 => Arch::X86,
        header::COFF_MACHINE_ARM64 => Arch::Arm64,
        header::COFF_MACHINE_ARM | header::COFF_MACHINE_ARMNT => Arch::Arm,
        header::COFF_MACHINE_RISCV32 => Arch::RiscV32,
        header::COFF_MACHINE_RISCV64 => Arch::RiscV64,
        header::COFF_MACHINE_POWERPC | header::COFF_MACHINE_POWERPCFP => Arch::Ppc32,
        _ => Arch::Unknown,
    }
}

pub fn pe_parse_all(data: &[u8]) -> ParseResult {
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
                    .unwrap_or("<invalid utf8>")
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

            let mut text_section: Option<(Vec<u8>, u64, Arch)> = None;
            let mut text_matches = 0usize;
            for section in &pe.sections {
                let name = std::str::from_utf8(&section.name)
                    .unwrap_or("")
                    .trim_matches('\0');
                if name == ".text" {
                    text_matches += 1;
                    let offset = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    let current_best = text_section.as_ref().map(|(b, _, _)| b.len());
                    if is_new_best(current_best, size)
                        && let Some(bytes) = checked_slice(data, offset, size)
                    {
                        let va = pe.image_base.saturating_add(section.virtual_address as u64);
                        let arch = pe_arch(pe.header.coff_header.machine);
                        text_section = Some((bytes, va, arch));
                    }
                }
            }
            if text_matches > 1 {
                sections.push(String::new());
                sections.push(format!(
                    "  Note: {} sections named \".text\" found; using the largest",
                    text_matches
                ));
            }

            (sections, imports, text_section)
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
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_data_does_not_panic() {
        let r = pe_parse_all(b"MZ garbage data that is not a valid PE");
        assert!(!r.0.is_empty());
    }

    #[test]
    fn text_section_on_garbage_returns_none() {
        let r = pe_parse_all(b"MZ garbage");
        assert!(r.2.is_none());
    }

    #[test]
    fn arch_mapping_known_machines() {
        assert_eq!(pe_arch(header::COFF_MACHINE_X86_64), Arch::X86_64);
        assert_eq!(pe_arch(header::COFF_MACHINE_X86), Arch::X86);
        assert_eq!(pe_arch(header::COFF_MACHINE_ARM64), Arch::Arm64);
        assert_eq!(pe_arch(header::COFF_MACHINE_ARM), Arch::Arm);
        assert_eq!(pe_arch(header::COFF_MACHINE_ARMNT), Arch::Arm);
        assert_eq!(pe_arch(header::COFF_MACHINE_RISCV32), Arch::RiscV32);
        assert_eq!(pe_arch(header::COFF_MACHINE_RISCV64), Arch::RiscV64);
        assert_eq!(pe_arch(header::COFF_MACHINE_POWERPC), Arch::Ppc32);
        assert_eq!(pe_arch(header::COFF_MACHINE_POWERPCFP), Arch::Ppc32);
    }

    #[test]
    fn arch_mapping_unknown_machine_is_unknown() {
        assert_eq!(pe_arch(0xDEAD), Arch::Unknown);
    }
}
