use goblin::elf::{Elf, header};

use crate::{
    analysis::disasm::Arch,
    formats::{
        ParseResult,
        util::{checked_slice, is_new_best},
    },
};

fn elf_arch(machine: u16, is_64: bool) -> Arch {
    match machine {
        header::EM_X86_64 => Arch::X86_64,
        header::EM_386 => Arch::X86,
        header::EM_AARCH64 => Arch::Arm64,
        header::EM_ARM => Arch::Arm,
        header::EM_MIPS => {
            if is_64 {
                Arch::Mips64
            } else {
                Arch::Mips
            }
        }
        _ => Arch::Unknown,
    }
}

pub fn elf_parse_all(data: &[u8]) -> ParseResult {
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
                let name = elf
                    .shdr_strtab
                    .get_at(section.sh_name)
                    .unwrap_or("<unreadable name>");
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

            let mut text_section: Option<(Vec<u8>, u64, Arch)> = None;
            let mut text_matches = 0usize;
            for section in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
                if name == ".text" {
                    text_matches += 1;
                    let offset = section.sh_offset as usize;
                    let size = section.sh_size as usize;
                    if let Some(bytes) = checked_slice(data, offset, size) {
                        let current_best = text_section.as_ref().map(|(b, _, _)| b.len());
                        if is_new_best(current_best, bytes.len()) {
                            let arch = elf_arch(elf.header.e_machine, elf.is_64);
                            text_section = Some((bytes, section.sh_addr, arch));
                        }
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
        Err(e) => (
            vec![format!("Parse error: {}", e)],
            vec![format!("Parse error: {}", e)],
            None,
        ),
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
        let r = elf_parse_all(b"\x7FELF garbage");
        assert!(r.2.is_none());
    }

    #[test]
    fn arch_mapping_known_machines() {
        assert_eq!(elf_arch(header::EM_X86_64, true), Arch::X86_64);
        assert_eq!(elf_arch(header::EM_386, false), Arch::X86);
        assert_eq!(elf_arch(header::EM_AARCH64, true), Arch::Arm64);
        assert_eq!(elf_arch(header::EM_ARM, false), Arch::Arm);
        assert_eq!(elf_arch(header::EM_MIPS, false), Arch::Mips);
        assert_eq!(elf_arch(header::EM_MIPS, true), Arch::Mips64);
    }

    #[test]
    fn arch_mapping_unknown_machine_is_unknown() {
        assert_eq!(elf_arch(0xDEAD, false), Arch::Unknown);
    }
}
