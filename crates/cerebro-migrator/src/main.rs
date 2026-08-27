use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use cerebro_migrator::{GoPackageGraph, MigratorError, PlanRequest};
use serde::Serialize;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cerebro-migrator: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), MigratorError> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(usage_error)?;
    let options = Options::parse(arguments)?;
    let input = read_input(options.input.as_deref())?;
    match command.as_str() {
        "discover" => {
            let graph =
                GoPackageGraph::from_go_list_json(input.as_slice(), options.module.as_deref())?;
            let condensation = graph.condense()?;
            write_output(
                options.output.as_deref(),
                &DiscoveryOutput {
                    graph,
                    condensation,
                },
            )
        }
        "plan" => {
            if options.module.is_some() {
                return Err(MigratorError::InvalidField {
                    field: "--module",
                    reason: "is valid only for discover".to_owned(),
                });
            }
            let request: PlanRequest = serde_json::from_slice(&input)?;
            let plan = request.plan()?;
            write_output(options.output.as_deref(), &plan)
        }
        _ => Err(usage_error()),
    }
}

#[derive(Serialize)]
struct DiscoveryOutput {
    graph: GoPackageGraph,
    condensation: cerebro_migrator::CondensedGoGraph,
}

#[derive(Default)]
struct Options {
    input: Option<String>,
    output: Option<String>,
    module: Option<String>,
}

impl Options {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, MigratorError> {
        let mut options = Self::default();
        let mut arguments = arguments.peekable();
        while let Some(argument) = arguments.next() {
            let target = match argument.as_str() {
                "--input" => &mut options.input,
                "--output" => &mut options.output,
                "--module" => &mut options.module,
                _ => return Err(usage_error()),
            };
            if target.is_some() {
                return Err(usage_error());
            }
            *target = Some(arguments.next().ok_or_else(usage_error)?);
        }
        Ok(options)
    }
}

fn read_input(path: Option<&str>) -> Result<Vec<u8>, MigratorError> {
    match path {
        Some(path) if path != "-" => fs::read(path).map_err(MigratorError::from),
        _ => {
            let mut input = Vec::new();
            io::stdin().read_to_end(&mut input)?;
            Ok(input)
        }
    }
}

fn write_output(path: Option<&str>, value: &impl Serialize) -> Result<(), MigratorError> {
    let mut encoded = serde_json::to_vec_pretty(value)?;
    encoded.push(b'\n');
    match path {
        Some(path) if path != "-" => fs::write(path, encoded).map_err(MigratorError::from),
        _ => io::stdout()
            .write_all(&encoded)
            .map_err(MigratorError::from),
    }
}

fn usage_error() -> MigratorError {
    MigratorError::InvalidField {
        field: "arguments",
        reason: "use `discover [--input FILE] [--output FILE] [--module PATH]` or `plan [--input FILE] [--output FILE]`".to_owned(),
    }
}
