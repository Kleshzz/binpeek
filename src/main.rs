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
#[command(about = "Terminal-based inary file inspector")]
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
        eprintln!("error: '{}' is not a file", cli.file.display());
        std::process::exit(1);
    }

    let data = match std::fs::read(&cli.file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not read '{}': {}", cli.file.display(), e);
            std::process::exit(1);
        }
    };

    if data.is_empty() {
        eprintln!("error: file '{}' is empty", cli.file.display());
        std::process::exit(1);
    }

    ui::run(cli.file.clone(), data);
}
