//! Capability-free source worker process.

#[path = "../source_execution.rs"]
mod source_execution;

use std::io::{self, Read, Write};

const MAX_WORKER_INPUT_BYTES: u64 = (8 << 20) + (64 << 10);

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = std::env::args()
        .nth(1)
        .ok_or("source worker command is required")?;
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_WORKER_INPUT_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_WORKER_INPUT_BYTES {
        return Err("source worker input exceeds the process bound".into());
    }
    let output = match command.as_str() {
        "plan" => source_execution::plan(&input)?,
        "decode" => source_execution::decode(&input)?,
        _ => return Err("source worker command is invalid".into()),
    };
    io::stdout().write_all(&output)?;
    Ok(())
}
