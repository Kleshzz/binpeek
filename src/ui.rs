use crate::app::{App, TAB_NAMES};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
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

pub fn run(mut app: App) {
    enable_raw_mode().unwrap();
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    loop {
        app.clamp_scroll();

        terminal.draw(|f| {
            let size = f.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(1),
                    Constraint::Length(1),
                ])
                .split(size);

            // ── Tab bar ──────────────────────────────────────────────────
            let tab_titles: Vec<Line> = TAB_NAMES
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let count = app.tabs[i].len();
                    Line::from(format!(" {} ({}) ", name, count))
                })
                .collect();

            let tabs_widget = Tabs::new(tab_titles)
                .select(app.tab)
                .block(Block::default().borders(Borders::ALL).title(format!(" binpeek — {} ", app.file_name)))
                .highlight_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .style(Style::default().fg(Color::Gray));
            f.render_widget(tabs_widget, chunks[0]);

            // ── Content ───────────────────────────────────────────────────
            let scroll_info = format!(
                " {}/{} ",
                app.scroll + 1,
                app.current_tab().len()
            );
            let content_block = Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", TAB_NAMES[app.tab]))
                .title_bottom(Line::from(scroll_info).right_aligned())
                .border_style(Style::default().fg(Color::DarkGray));

            let visible_height = chunks[1].height.saturating_sub(2) as usize;

            let items: Vec<ListItem> = app
                .current_tab()
                .iter()
                .skip(app.scroll as usize)
                .take(visible_height)
                .map(|l| ListItem::new(l.as_str()))
                .collect();

            let list = List::new(items).block(content_block);
            f.render_widget(list, chunks[1]);

            // ── Status bar ────────────────────────────────────────────────
            let help = Paragraph::new(Span::styled(
                " [1-5] Tabs  [↑↓] Scroll  [PgUp/PgDn] Page  [Home] Top  [q] Quit",
                Style::default().fg(Color::DarkGray),
            ));
            f.render_widget(help, chunks[2]);
        }).unwrap();

        if event::poll(std::time::Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                // Игнорируем release-события (важно для Windows)
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('1') => app.go_to_tab(0),
                    KeyCode::Char('2') => app.go_to_tab(1),
                    KeyCode::Char('3') => app.go_to_tab(2),
                    KeyCode::Char('4') => app.go_to_tab(3),
                    KeyCode::Char('5') => app.go_to_tab(4),
                    KeyCode::Down      => app.scroll_down(1),
                    KeyCode::Up        => app.scroll_up(1),
                    KeyCode::PageDown  => app.scroll_down(20),
                    KeyCode::PageUp    => app.scroll_up(20),
                    KeyCode::Home      => app.scroll = 0,
                    KeyCode::End       => app.scroll = app.max_scroll(),
                    KeyCode::Tab       => app.go_to_tab((app.tab + 1) % TAB_NAMES.len()),
                    KeyCode::BackTab   => app.go_to_tab((app.tab + TAB_NAMES.len() - 1) % TAB_NAMES.len()),
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode().unwrap();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).unwrap();
}
