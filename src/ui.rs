use std::thread::JoinHandle;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs},
};

use crate::app::{App, Progress, TAB_NAMES};

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
    }
}

pub fn run_loading(progress: &Progress, handle: JoinHandle<crate::app::App>) {
    enable_raw_mode().unwrap();
    let _guard = TerminalGuard;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    let _handle = std::thread::spawn(move || {
        let result = handle.join().unwrap();
        tx.send(result).unwrap();
    });

    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let mut frame: usize = 0;

    loop {
        if let Ok(app) = rx.try_recv() {
            run(app, &mut terminal);
            return; // _guard drops here, raw mode disabled/alt screen left exactly once
        }

        let pct = crate::app::LoadProgress::percent(progress);
        let label = crate::app::LoadProgress::label(progress);
        let spin = spinner[frame % spinner.len()];
        frame += 1;

        terminal
            .draw(|f| {
                let size = f.area();

                let bg = Block::default().style(Style::default().bg(Color::Black));
                f.render_widget(bg, size);

                let popup_width = size.width.min(60);
                let popup_height = 9u16;
                let popup_x = (size.width.saturating_sub(popup_width)) / 2;
                let popup_y = (size.height.saturating_sub(popup_height)) / 2;

                let popup_area = ratatui::layout::Rect {
                    x: popup_x,
                    y: popup_y,
                    width: popup_width,
                    height: popup_height,
                };

                let popup_block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(Span::styled(
                        " binpeek ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ));
                f.render_widget(popup_block, popup_area);

                let inner = ratatui::layout::Rect {
                    x: popup_x + 2,
                    y: popup_y + 1,
                    width: popup_width.saturating_sub(4),
                    height: popup_height.saturating_sub(2),
                };

                let status_line = format!("  {}  {}", spin, label);
                let status =
                    Paragraph::new(Span::styled(status_line, Style::default().fg(Color::White)));
                f.render_widget(
                    status,
                    ratatui::layout::Rect {
                        x: inner.x,
                        y: inner.y + 1,
                        width: inner.width,
                        height: 1,
                    },
                );

                let bar_width = inner.width as usize;
                let filled = (bar_width * pct.min(100) as usize / 100).min(bar_width);
                let empty = bar_width.saturating_sub(filled);

                let bar_filled = Span::styled("█".repeat(filled), Style::default().fg(Color::Cyan));
                let bar_empty =
                    Span::styled("░".repeat(empty), Style::default().fg(Color::DarkGray));

                let bar_line = Line::from(vec![bar_filled, bar_empty]);
                let bar = Paragraph::new(bar_line);
                f.render_widget(
                    bar,
                    ratatui::layout::Rect {
                        x: inner.x,
                        y: inner.y + 3,
                        width: inner.width,
                        height: 1,
                    },
                );

                let pct_text = Paragraph::new(Span::styled(
                    format!("  {}%", pct),
                    Style::default().fg(Color::DarkGray),
                ));
                f.render_widget(
                    pct_text,
                    ratatui::layout::Rect {
                        x: inner.x,
                        y: inner.y + 4,
                        width: inner.width,
                        height: 1,
                    },
                );
            })
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(80));
    }
}

pub fn run(mut app: App, terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) {
    loop {
        app.clamp_scroll();
        terminal
            .draw(|f| {
                let size = f.area();
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(1),
                        Constraint::Length(1),
                    ])
                    .split(size);

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
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(format!(" binpeek — {} ", app.file_name)),
                    )
                    .highlight_style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                    .style(Style::default().fg(Color::Gray));
                f.render_widget(tabs_widget, chunks[0]);

                let scroll_info = if app.current_tab().is_empty() {
                    " 0/0 ".to_string()
                } else {
                    format!(" {}/{} ", app.scroll + 1, app.current_tab().len())
                };
                let content_block = Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", TAB_NAMES[app.tab]))
                    .title_bottom(Line::from(scroll_info).right_aligned())
                    .border_style(Style::default().fg(Color::DarkGray));

                let visible_height = chunks[1].height.saturating_sub(2) as usize;

                let items: Vec<ListItem> = app
                    .current_tab()
                    .iter()
                    .skip(app.scroll)
                    .take(visible_height)
                    .map(|l| ListItem::new(l.as_str()))
                    .collect();

                let list = List::new(items).block(content_block);
                f.render_widget(list, chunks[1]);

                let help = Paragraph::new(Span::styled(
                    " [1-5] Tabs  [↑↓] Scroll  [PgUp/PgDn] Page  [Home] Top  [q] Quit",
                    Style::default().fg(Color::DarkGray),
                ));
                f.render_widget(help, chunks[2]);
            })
            .unwrap();

        #[allow(clippy::collapsible_if)]
        if event::poll(std::time::Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
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
                    KeyCode::Down => app.scroll_down(1),
                    KeyCode::Up => app.scroll_up(1),
                    KeyCode::PageDown => app.scroll_down(20),
                    KeyCode::PageUp => app.scroll_up(20),
                    KeyCode::Home => app.scroll = 0,
                    KeyCode::End => app.scroll = app.max_scroll(),
                    KeyCode::Tab => app.go_to_tab((app.tab + 1) % TAB_NAMES.len()),
                    KeyCode::BackTab => {
                        app.go_to_tab((app.tab + TAB_NAMES.len() - 1) % TAB_NAMES.len())
                    }
                    _ => {}
                }
            }
        }
    }
}
