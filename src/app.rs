use crate::analysis::{detector, disasm, entropy, lang, strings};
use crate::formats;
use std::sync::{Arc, Mutex};

pub const TAB_NAMES: [&str; 5] = ["Overview", "Sections", "Imports", "Strings", "Disasm"];

pub struct App {
    pub tab: usize,
    pub scroll: u16,
    pub tabs: [Vec<String>; 5],
    pub file_name: String,
}

pub type Progress = Arc<Mutex<LoadProgress>>;

pub struct LoadProgress {
    pub steps_done: u8,
    pub total: u8,
    pub current: &'static str,
}

impl LoadProgress {
    pub fn new() -> Progress {
        Arc::new(Mutex::new(Self {
            steps_done: 0,
            total: 4,
            current: "Starting...",
        }))
    }

    pub fn percent(p: &Progress) -> u8 {
        let p = p.lock().unwrap();
        if p.total == 0 {
            return 0;
        }
        (p.steps_done as u16 * 100 / p.total as u16) as u8
    }

    pub fn label(p: &Progress) -> String {
        p.lock().unwrap().current.to_string()
    }
}

impl App {
    pub fn new(path: &std::path::Path, data: &[u8], progress: &Progress) -> Self {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
        let is_elf = data.len() >= 4 && data[..4] == [0x7F, 0x45, 0x4C, 0x46];
        let is_macho = data.len() >= 4
            && (data[..4] == [0xFE, 0xED, 0xFA, 0xCE]
                || data[..4] == [0xFE, 0xED, 0xFA, 0xCF]
                || data[..4] == [0xCE, 0xFA, 0xED, 0xFE]
                || data[..4] == [0xCF, 0xFA, 0xED, 0xFE]
                || data[..4] == [0xCA, 0xFE, 0xBA, 0xBE]
                || data[..4] == [0xBE, 0xBA, 0xFE, 0xCA]);

        let data_arc = Arc::new(data.to_vec());

        let d1 = data_arc.clone();
        let p1 = progress.clone();
        let t_strings = std::thread::spawn(move || {
            {
                let mut p = p1.lock().unwrap();
                p.current = "Extracting strings...";
            }
            let r = strings::extract(&d1, 5);
            {
                let mut p = p1.lock().unwrap();
                p.steps_done += 1;
            }
            r
        });

        let d2 = data_arc.clone();
        let p2 = progress.clone();
        let t_sections = std::thread::spawn(move || {
            {
                let mut p = p2.lock().unwrap();
                p.current = "Parsing sections & imports...";
            }
            let r = std::panic::catch_unwind(|| {
                if is_pe {
                    formats::pe_parse_all(&d2)
                } else if is_elf {
                    formats::elf_parse_all(&d2)
                } else if is_macho {
                    formats::macho_parse_all(&d2)
                } else {
                    (
                        vec!["  Not supported for this format".to_string()],
                        vec!["  Not supported for this format".to_string()],
                    )
                }
            })
            .unwrap_or_else(|_| {
                (
                    vec!["  Parse error: binary appears malformed or heavily packed".to_string()],
                    vec!["  Import table unavailable".to_string()],
                )
            });
            {
                let mut p = p2.lock().unwrap();
                p.steps_done += 1;
            }
            r
        });

        let d3 = data_arc.clone();
        let p3 = progress.clone();
        let t_disasm = std::thread::spawn(move || {
            {
                let mut p = p3.lock().unwrap();
                p.current = "Disassembling .text...";
            }
            let r = std::panic::catch_unwind(|| {
                let text = if is_pe {
                    formats::pe_text_section(&d3)
                } else if is_elf {
                    formats::elf_text_section(&d3)
                } else if is_macho {
                    formats::macho_text_section(&d3)
                } else {
                    None
                };
                match text {
                    Some((bytes, addr, is_64)) => disasm::disassemble(&bytes, is_64, addr),
                    None => vec!["  .text section not found or format not supported".to_string()],
                }
            })
            .unwrap_or_else(|_| vec!["  Disassembly failed: binary appears malformed".to_string()]);
            {
                let mut p = p3.lock().unwrap();
                p.steps_done += 1;
            }
            r
        });

        {
            let mut p = progress.lock().unwrap();
            p.current = "Calculating entropy...";
        }
        let ent = entropy::calculate(&data_arc);
        let format = detector::detect_with_path(&data_arc, path);
        let lang_info = lang::detect(&data_arc);
        let overview = build_overview(&file_name, data_arc.len(), ent, &format, &lang_info);
        {
            let mut p = progress.lock().unwrap();
            p.steps_done += 1;
            p.current = "Finishing...";
        }

        let strings = t_strings.join().unwrap();
        let (sections, imports) = t_sections.join().unwrap();
        let disasm = t_disasm.join().unwrap();

        {
            let mut p = progress.lock().unwrap();
            p.steps_done = p.total;
            p.current = "Done";
        }

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
        self.scroll = self.scroll.saturating_add(n).min(self.max_scroll());
    }

    pub fn scroll_up(&mut self, n: u16) {
        self.scroll = self.scroll.saturating_sub(n);
    }

    pub fn go_to_tab(&mut self, idx: usize) {
        if idx < TAB_NAMES.len() {
            self.tab = idx;
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
        format!(
            "  Size       : {} bytes  ({:.1} KB)",
            size,
            size as f64 / 1024.0
        ),
        format!("  Format     : {}", format),
        format!("  Language   : {}", info.language),
        format!("  Entropy    : {:.4}  — {}", ent, entropy::label(ent)),
    ];

    if let Some(packer) = info.packer {
        lines.push(format!(
            "  Packer     : {}  (upx -d <file> to unpack)",
            packer
        ));
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
    lines.push("    q / Esc          — quit".to_string());

    lines
}
