use crate::{detector, disasm, entropy, formats, lang, strings};
use std::sync::Arc;

pub const TAB_NAMES: [&str; 5] = ["Overview", "Sections", "Imports", "Strings", "Disasm"];

pub struct App {
    pub tab: usize,
    pub scroll: u16,
    pub tabs: [Vec<String>; 5],
    pub file_name: String,
}

impl App {
    pub fn new(path: &std::path::Path, data: &[u8]) -> Self {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let is_pe  = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
        let is_elf = data.len() >= 4 && data[..4] == [0x7F, 0x45, 0x4C, 0x46];

        let data_arc = Arc::new(data.to_vec());

        // Strings — самое медленное на больших файлах, запускаем первым
        let d1 = data_arc.clone();
        let t_strings = std::thread::spawn(move || strings::extract(&d1, 5));

        // Sections + Imports
        let d2 = data_arc.clone();
        let t_sections = std::thread::spawn(move || {
            if is_pe {
                formats::pe_parse_all(&d2)
            } else if is_elf {
                formats::elf_parse_all(&d2)
            } else {
                (
                    vec!["  Not supported for this format".to_string()],
                    vec!["  Not supported for this format".to_string()],
                )
            }
        });

        // Disasm
        let d3 = data_arc.clone();
        let t_disasm = std::thread::spawn(move || {
            let text = if is_pe {
                formats::pe_text_section(&d3)
            } else if is_elf {
                formats::elf_text_section(&d3)
            } else {
                None
            };
            match text {
                Some((bytes, addr, is_64)) => disasm::disassemble(&bytes, is_64, addr),
                None => vec!["  .text section not found or format not supported".to_string()],
            }
        });

        // Overview считаем в главном потоке пока остальные работают
        let ent       = entropy::calculate(&data_arc);
        let format    = detector::detect_str(&data_arc);
        let lang_info = lang::detect(&data_arc);
        let overview  = build_overview(&file_name, data_arc.len(), ent, &format, &lang_info);

        let strings             = t_strings.join().unwrap();
        let (sections, imports) = t_sections.join().unwrap();
        let disasm              = t_disasm.join().unwrap();

        Self {
            tab: 0,
            scroll: 0,
            tabs: [overview, sections, imports, strings, disasm],
            file_name,
        }
    }

    pub fn current_tab(&self) -> &Vec<String> {
        &self.tabs[self.tab]
    }

    pub fn max_scroll(&self) -> u16 {
        self.current_tab().len().saturating_sub(1) as u16
    }

    pub fn clamp_scroll(&mut self) {
        let max = self.max_scroll();
        if self.scroll > max {
            self.scroll = max;
        }
    }

    pub fn scroll_down(&mut self, n: u16) {
        let max = self.max_scroll();
        self.scroll = self.scroll.saturating_add(n).min(max);
    }

    pub fn scroll_up(&mut self, n: u16) {
        self.scroll = self.scroll.saturating_sub(n);
    }

    pub fn go_to_tab(&mut self, idx: usize) {
        if idx < TAB_NAMES.len() {
            self.tab    = idx;
            self.scroll = 0;
        }
    }
}

fn build_overview(
    name: &str,
    size: usize,
    ent: f64,
    format: &str,
    info: &lang::FileInfo,
) -> Vec<String> {
    let mut lines = vec![
        String::new(),
        format!("  File       : {}", name),
        format!("  Size       : {} bytes  ({:.1} KB)", size, size as f64 / 1024.0),
        format!("  Format     : {}", format),
        format!("  Language   : {}", info.language),
        format!("  Entropy    : {:.4}  — {}", ent, entropy::label(ent)),
    ];

    if let Some(packer) = info.packer {
        lines.push(format!("  Packer     : {}  (upx -d <file> to unpack)", packer));
    }
    if let Some(obf) = info.obfuscator {
        lines.push(format!("  Obfuscator : {}", obf));
    }

    lines.push(String::new());
    lines.push("  ─────────────────────────────".to_string());
    lines.push("  Controls:".to_string());
    lines.push("    1-5              — switch tabs".to_string());
    lines.push("    ↑ ↓              — scroll line".to_string());
    lines.push("    PgUp / PgDn      — scroll page".to_string());
    lines.push("    Home / End       — top / bottom".to_string());
    lines.push("    Tab / Shift+Tab  — next / prev tab".to_string());
    lines.push("    q / Esc          — quit".to_string());

    lines
}
