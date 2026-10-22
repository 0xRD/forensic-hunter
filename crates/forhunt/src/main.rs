//! `forhunt`: the Forensic Hunter command-line interface.

use std::process::ExitCode;

use clap::Parser;

mod cli;
mod cmd;
mod common;
mod facets;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    let args = cli::Cli::parse();
    let r = match args.cmd {
        cli::Cmd::Parse(a) => cmd::dump::parse(a),
        cli::Cmd::Search(a) => cmd::dump::search(a),
        cli::Cmd::Stats(a) => cmd::stats::run(a),
        cli::Cmd::Timeline(a) => cmd::timeline::run(a),
        cli::Cmd::Show(a) => cmd::show::run(a),
        cli::Cmd::Hayabusa(a) => cmd::hayabusa::run(a),
        cli::Cmd::Checklist(a) => cmd::checklist::run(a),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let code = e
                .downcast_ref::<common::Fail>()
                .map(|f| f.code)
                .unwrap_or(common::exit::ERROR);
            eprintln!("forhunt: error: {e:#}");
            ExitCode::from(code as u8)
        }
    }
}
