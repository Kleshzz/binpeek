use capstone::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
    RiscV32,
    RiscV64,
    Ppc32,
    Ppc64,
    Unknown,
}

impl Arch {
    pub fn label(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm => "ARM",
            Arch::Arm64 => "ARM64",
            Arch::Mips => "MIPS",
            Arch::Mips64 => "MIPS64",
            Arch::RiscV32 => "RISC-V32",
            Arch::RiscV64 => "RISC-V64",
            Arch::Ppc32 => "PowerPC32",
            Arch::Ppc64 => "PowerPC64",
            Arch::Unknown => "Unknown",
        }
    }
}

pub fn disassemble(data: &[u8], arch: Arch, base_addr: u64) -> Vec<String> {
    let cs = match arch {
        Arch::X86 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(false)
            .build(),
        Arch::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(false)
            .build(),
        Arch::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(false)
            .build(),
        Arch::Arm64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(false)
            .build(),
        Arch::Mips => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .detail(false)
            .build(),
        Arch::Mips64 => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .detail(false)
            .build(),
        Arch::RiscV32 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .detail(false)
            .build(),
        Arch::RiscV64 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .detail(false)
            .build(),
        Arch::Ppc32 => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode32)
            .endian(capstone::Endian::Big)
            .detail(false)
            .build(),
        Arch::Ppc64 => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode64)
            .endian(capstone::Endian::Big)
            .detail(false)
            .build(),
        Arch::Unknown => {
            return vec![
                "  Architecture not recognized: disassembly not supported for this binary"
                    .to_string(),
            ];
        }
    };

    let cs = match cs {
        Ok(c) => c,
        Err(e) => return vec![format!("  Capstone init error: {}", e)],
    };

    let limit = data.len().min(64 * 1024);
    let insns = match cs.disasm_all(&data[..limit], base_addr) {
        Ok(i) => i,
        Err(e) => return vec![format!("  Disassembly error: {}", e)],
    };

    let total_kb = data.len() as f64 / 1024.0;
    let shown_kb = limit as f64 / 1024.0;

    let mut lines = vec![
        format!("  Base address : 0x{:X}", base_addr),
        format!("  Architecture : {}", arch.label()),
        format!(
            "  Section size : {:.1} KB total, showing first {:.1} KB ({} instructions)",
            total_kb,
            shown_kb,
            insns.len()
        ),
        String::new(),
        format!("  {:18}  {:24}  {}", "Address", "Bytes", "Instruction"),
        format!("  {}", "-".repeat(60)),
    ];

    for insn in insns.as_ref() {
        let bytes_str = insn
            .bytes()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(format!(
            "  0x{:016X}  {:24}  {} {}",
            insn.address(),
            bytes_str,
            insn.mnemonic().unwrap_or("?"),
            insn.op_str().unwrap_or("")
        ));
    }

    if lines.len() <= 6 {
        lines.push("  No instructions found".to_string());
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_arch_returns_message_not_panic() {
        let r = disassemble(&[0x90, 0x90], Arch::Unknown, 0x1000);
        assert_eq!(r.len(), 1);
        assert!(r[0].contains("not recognized"));
    }

    #[test]
    fn x86_64_disassembles_nop() {
        let r = disassemble(&[0x90], Arch::X86_64, 0x1000);
        assert!(r.iter().any(|l| l.contains("nop")));
    }

    #[test]
    fn arm64_disassembles_known_bytes() {
        let r = disassemble(&[0x20, 0xf0, 0x5f, 0xf8], Arch::Arm64, 0x1000);
        assert!(r.iter().any(|l| l.contains("Architecture")));
        assert!(
            r.len() > 6,
            "expected at least header + one instruction line"
        );
    }

    #[test]
    fn empty_code_does_not_panic() {
        let r = disassemble(&[], Arch::X86_64, 0x1000);
        assert!(r.iter().any(|l| l.contains("No instructions found")));
    }

    #[test]
    fn label_matches_arch() {
        assert_eq!(Arch::X86_64.label(), "x86_64");
        assert_eq!(Arch::Arm64.label(), "ARM64");
        assert_eq!(Arch::Unknown.label(), "Unknown");
    }
}
