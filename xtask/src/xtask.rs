use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand};
use xshell::{cmd, Shell};

#[derive(Debug, Parser)]
struct XTask {
    #[clap(subcommand)]
    cmd: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Format, build, test, and lint.
    CI,

    // Run benchmarks.
    Bench {
        /// Additional arguments.
        #[arg(action(ArgAction::Append), allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let xtask = XTask::parse();

    let sh = Shell::new()?;
    sh.change_dir(project_root());

    match xtask.cmd.unwrap_or(Command::CI) {
        Command::CI => ci(&sh),
        Command::Bench { args } => bench(&sh, args),
    }
}

fn ci(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo fmt --check").run()?;
    cmd!(sh, "cargo build --all-targets --all-features").run()?;
    cmd!(sh, "cargo test").run()?;
    cmd!(sh, "cargo clippy --all-features --all-targets").run()?;

    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const RUSTFLAGS: &str = "-C target-cpu=native";

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
const RUSTFLAGS: &str = "";

fn bench(sh: &Shell, args: Vec<String>) -> Result<()> {
    cmd!(sh, "cargo bench -p benchmarks {args...}")
        .env("RUSTFLAGS", RUSTFLAGS)
        .env("DIVAN_BYTES_FORMAT", "binary")
        .env("DIVAN_TIMER", "tsc")
        .env("DIVAN_MIN_TIME", "1")
        .env("DIVAN_SKIP_EXT_TIME", "true")
        .run()?;

    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(
        &env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_owned()),
    )
    .ancestors()
    .nth(1)
    .unwrap()
    .to_path_buf()
}
