//! Aegis — production readiness audit CLI.
//!
//! `aegis scan <path>`  — static audit of a codebase (secrets, deps, test debt, config, CI)
//! `aegis probe <url>`  — live audit of an HTTP endpoint (TLS, headers, cookies, latency)

mod probe;
mod report;
mod scan;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use report::Report;
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aegis",
    version,
    about = "Production readiness audit: scan a codebase or probe a live URL",
    long_about = "Aegis grades a project the way a production-rescue engineer does on day one:\n\
                  what leaks, what's unpinned, what's untested, what's misconfigured, and\n\
                  what the live endpoint tells an attacker for free."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output format
    #[arg(long, global = true, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Exit non-zero if the overall score is below this threshold (0-100)
    #[arg(long, global = true)]
    fail_under: Option<f64>,
}

#[derive(Subcommand)]
enum Command {
    /// Statically audit a project directory
    Scan {
        /// Path to the project root
        path: PathBuf,
    },
    /// Probe a live HTTP(S) endpoint
    Probe {
        /// URL to probe (e.g. https://example.com)
        url: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Markdown,
}

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("aegis: error: {e:#}");
            std::process::exit(2);
        }
    }
}

fn run(cli: &Cli) -> Result<i32> {
    let report = match &cli.command {
        Command::Scan { path } => scan::run(path)?,
        Command::Probe { url } => {
            let resp = probe::fetch(url)?;
            probe::analyze(url, &resp)
        }
    };

    emit(&report, cli.format);

    if let Some(threshold) = cli.fail_under {
        if report.score < threshold {
            eprintln!(
                "aegis: score {:.0} is below threshold {:.0}",
                report.score, threshold
            );
            return Ok(1);
        }
    }
    Ok(0)
}

fn emit(report: &Report, format: Format) {
    match format {
        Format::Json => println!("{}", report.to_json()),
        Format::Markdown => println!("{}", report.to_markdown()),
        Format::Text => {
            let color = std::io::stdout().is_terminal();
            print!("{}", report.render_text(color));
        }
    }
}
