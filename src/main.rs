use anyhow::Result;
use bitbeak::{run, Args};
use clap::Parser;

fn main() -> Result<()> {
    let args = Args::parse();
    run(args)
}
