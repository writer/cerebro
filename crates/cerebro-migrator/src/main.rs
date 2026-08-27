use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use cerebro_migrator::{
    DeletionManifest, DeletionManifestBuildRequest, GoPackageGraph, MigratorError, PlanRequest,
    apply_deletion_manifest, verify_deletion_manifest,
};
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
            reject_root(&options)?;
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
            reject_discovery_options(&options)?;
            let request: PlanRequest = serde_json::from_slice(&input)?;
            let plan = request.plan()?;
            write_output(options.output.as_deref(), &plan)
        }
        "bind-manifest" => {
            reject_module(&options)?;
            let root = options.root.as_deref().ok_or_else(usage_error)?;
            let request: DeletionManifestBuildRequest = serde_json::from_slice(&input)?;
            let manifest = request.bind(root.as_ref())?;
            write_output(options.output.as_deref(), &manifest)
        }
        "verify" => {
            reject_module(&options)?;
            let root = options.root.as_deref().ok_or_else(usage_error)?;
            let manifest = DeletionManifest::from_json_slice(&input)?;
            let preflight = verify_deletion_manifest(root.as_ref(), &manifest)?;
            write_output(options.output.as_deref(), &preflight)
        }
        "apply" => {
            reject_module(&options)?;
            if options.output.is_some() {
                return Err(MigratorError::InvalidField {
                    field: "--output",
                    reason: "apply emits its receipt to stdout to avoid unrelated file mutation"
                        .to_owned(),
                });
            }
            let root = options.root.as_deref().ok_or_else(usage_error)?;
            let manifest = DeletionManifest::from_json_slice(&input)?;
            let receipt = apply_deletion_manifest(root.as_ref(), &manifest)?;
            write_output(None, &receipt)
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
    root: Option<String>,
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
                "--root" => &mut options.root,
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

fn reject_root(options: &Options) -> Result<(), MigratorError> {
    if options.root.is_some() {
        return Err(MigratorError::InvalidField {
            field: "--root",
            reason: "is valid only for bind-manifest, verify, and apply".to_owned(),
        });
    }
    Ok(())
}

fn reject_module(options: &Options) -> Result<(), MigratorError> {
    if options.module.is_some() {
        return Err(MigratorError::InvalidField {
            field: "--module",
            reason: "is valid only for discover".to_owned(),
        });
    }
    Ok(())
}

fn reject_discovery_options(options: &Options) -> Result<(), MigratorError> {
    reject_module(options)?;
    reject_root(options)
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
        reason: "use `discover [--input FILE] [--output FILE] [--module PATH]`, `plan [--input FILE] [--output FILE]`, `bind-manifest --root REPOSITORY [--input FILE] [--output FILE]`, `verify --root REPOSITORY [--input FILE] [--output FILE]`, or `apply --root REPOSITORY [--input FILE]`".to_owned(),
    }
}
