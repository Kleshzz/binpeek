use clap::Parser;
use std::path::PathBuf;

mod detector;
mod entropy;
mod formats;
mod strings;
mod ui;

#[derive(Parser)]
#[command(name = "binpeek")]
#[command(version)]
#[command(about = "Terminal-based binary file inspector")]
pub struct Cli {
    pub file: PathBuf,
}

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

    let data = match std::fs::read(&cli.file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: could not read '{}': {}", cli.file.display(), e);
            std::process::exit(1);
        }
    };

    if data.is_empty() {
        eprintln!("Error: file '{}' is empty", cli.file.display());
        std::process::exit(1);
    }

    if data.len() > 100 * 1024 * 1024 {
        eprintln!("Warning: large file ({:.0} MB), analysis may be slow", data.len() as f64 / 1_048_576.0);
    }

    ui::run(cli.file.clone(), data);
}
