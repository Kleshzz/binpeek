use std::path::PathBuf;

use clap::Parser;

mod analysis;
mod app;
mod formats;
mod ui;

#[derive(Parser)]
#[command(name = "binpeek")]
#[command(version)]
#[command(about = "Terminal-based binary file inspector")]
pub struct Cli {
    pub file: PathBuf,
}

use std::sync::Arc;

fn main() {
    let cli = Cli::parse();

    if !cli.file.exists() {
        eprintln!("Error: file not found");
        std::process::exit(1);
    }

    if !cli.file.is_file() {
        eprintln!("Error: '{}' is not a file", cli.file.display());
        std::process::exit(1);
    }

    let metadata = match std::fs::metadata(&cli.file) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "Error: could not get metadata for '{}': {}",
                cli.file.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let size = metadata.len();
    if size == 0 {
        eprintln!("Error: file '{}' is empty", cli.file.display());
        std::process::exit(1);
    }

    if size > 100 * 1024 * 1024 {
        eprintln!(
            "Warning: large file ({:.0} MB), analysis may be slow",
            size as f64 / 1_048_576.0
        );
    }

    let data = match std::fs::read(&cli.file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: could not read '{}': {}", cli.file.display(), e);
            std::process::exit(1);
        }
    };

    let data_arc = Arc::new(data);
    let progress = app::LoadProgress::new();
    let p = progress.clone();
    let path = cli.file.clone();

    let d_arc = data_arc.clone();
    let handle = std::thread::spawn(move || app::App::new(&path, d_arc, &p));

    ui::run_loading(&progress, handle);
}
