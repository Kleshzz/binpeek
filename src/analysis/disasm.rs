use capstone::prelude::*;

pub fn disassemble(data: &[u8], is_64: bool, base_addr: u64) -> Vec<String> {
    let cs = Capstone::new()
        .x86()
        .mode(if is_64 {
            arch::x86::ArchMode::Mode64
        } else {
            arch::x86::ArchMode::Mode32
        })
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build();

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
        format!(
            "  Mode         : {}",
            if is_64 { "64-bit" } else { "32-bit" }
        ),
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
