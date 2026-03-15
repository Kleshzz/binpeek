use crate::{detector, entropy, formats, strings};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs},
    Terminal,
};
use std::path::PathBuf;

pub fn run(path: PathBuf, data: Vec<u8>) {
    enable_raw_mode().unwrap();
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let file_size = data.len();
    let ent = entropy::calculate(&data);
    let format = detector::detect_str(&data);

    let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
    let is_elf = data.len() >= 4 && &data[..4] == &[0x7F, 0x45, 0x4C, 0x46];

    let overview_lines = build_overview(&file_name, file_size, ent, &format);
    let sections_lines = if is_pe {
        formats::pe_sections_str(&data)
    } else if is_elf {
        formats::elf_sections_str(&data)
    } else {
        vec!["  Not supported for this format".to_string()]
    };
    let imports_lines = if is_pe {
        formats::pe_imports_str(&data)
    } else if is_elf {
        formats::elf_imports_str(&data)
    } else {
        vec!["  Not supported for this format".to_string()]
    };
    let strings_lines = strings::extract(&data, 5);

    let tabs = vec!["Overview", "Sections", "Imports", "Strings"];
    let mut tab: usize = 0;
    let mut scroll: u16 = 0;

    loop {
        terminal.draw(|f| {
            let size = f.area();

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(1)])
                .split(size);

            // Tabs
            let tab_titles: Vec<Line> = tabs.iter().map(|t| Line::from(*t)).collect();
            let tabs_widget = Tabs::new(tab_titles)
                .select(tab)
                .block(Block::default().borders(Borders::ALL).title(" binpeek "))
                .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .style(Style::default().fg(Color::Gray));
            f.render_widget(tabs_widget, chunks[0]);

            // Content
            let content_block = Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", tabs[tab]))
                .border_style(Style::default().fg(Color::DarkGray));

            let current_list = match tab {
                0 => &overview_lines,
                1 => &sections_lines,
                2 => &imports_lines,
                3 => &strings_lines,
                _ => &overview_lines,
            };

            let items: Vec<ListItem> = current_list
                .iter()
                .skip(scroll as usize)
                .map(|l| ListItem::new(l.as_str()))
                .collect();

            let list = List::new(items).block(content_block);
            f.render_widget(list, chunks[1]);

            // Help bar
            let help = Paragraph::new(Span::styled(
                " [1-4] Switch tabs  [↑↓ / PgUp/PgDn] Scroll  [q] Quit",
                Style::default().fg(Color::DarkGray),
            ));
            f.render_widget(help, chunks[2]);
        }).unwrap();

        if event::poll(std::time::Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('1') => { tab = 0; scroll = 0; }
                    KeyCode::Char('2') => { tab = 1; scroll = 0; }
                    KeyCode::Char('3') => { tab = 2; scroll = 0; }
                    KeyCode::Char('4') => { tab = 3; scroll = 0; }
                    KeyCode::Down  => scroll = scroll.saturating_add(1),
                    KeyCode::Up    => scroll = scroll.saturating_sub(1),
                    KeyCode::PageDown => scroll = scroll.saturating_add(20),
                    KeyCode::PageUp   => scroll = scroll.saturating_sub(20),
                    KeyCode::Home  => scroll = 0,
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode().unwrap();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
}

fn build_overview(name: &str, size: usize, ent: f64, format: &str) -> Vec<String> {
    vec![
        String::new(),
        format!("  File    : {}", name),
        format!("  Size    : {} bytes  ({:.1} KB)", size, size as f64 / 1024.0),
        format!("  Format  : {}", format),
        format!("  Entropy : {:.4}  — {}", ent, entropy::label(ent)),
        String::new(),
        "  ─────────────────────────────".to_string(),
        "  Controls:".to_string(),
        "    1-4              — switch tabs".to_string(),
        "    ↑ ↓              — scroll line".to_string(),
        "    PgUp / PgDn      — scroll page".to_string(),
        "    Home             — scroll to top".to_string(),
        "    q                — quit".to_string(),
    ]
}
