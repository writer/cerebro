use cerebro_graphactiongen::{
    DEFAULT_CATALOG_PATH, DEFAULT_OUTPUT_PATH, ensure_supported_platform, generate,
    read_generated_file, write_generated_file,
};
use std::env;
use std::error::Error as StdError;
use std::fmt;
use std::path::PathBuf;

const USAGE: &str =
    "usage: graphactiongen [--root PATH] [--catalog PATH] [--output PATH] (--write|--check)";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Write,
    Check,
}

#[derive(Debug, Eq, PartialEq)]
struct Options {
    root: PathBuf,
    catalog: PathBuf,
    output: PathBuf,
    mode: Mode,
}

#[derive(Debug, Eq, PartialEq)]
enum ParseResult {
    Run(Options),
    Help,
}

#[derive(Debug, Eq, PartialEq)]
enum CliError {
    MissingMode,
    ConflictingModes,
    MissingValue(&'static str),
    UnknownArgument(String),
    Operation(String),
    Stale(PathBuf),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMode => formatter.write_str("one of --write or --check is required"),
            Self::ConflictingModes => {
                formatter.write_str("--write and --check cannot be used together")
            }
            Self::MissingValue(flag) => write!(formatter, "{flag} requires a value"),
            Self::UnknownArgument(argument) => write!(formatter, "unknown argument {argument:?}"),
            Self::Operation(message) => formatter.write_str(message),
            Self::Stale(path) => write!(
                formatter,
                "{} is stale; run `make graph-action-generate`",
                path.display()
            ),
        }
    }
}

impl StdError for CliError {}

fn main() {
    match parse_args(env::args().skip(1)) {
        Ok(ParseResult::Help) => println!("{USAGE}"),
        Ok(ParseResult::Run(options)) => {
            if let Err(error) = run(&options) {
                eprintln!("graphactiongen: {error}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("graphactiongen: {error}\n{USAGE}");
            std::process::exit(2);
        }
    }
}

fn run(options: &Options) -> Result<(), CliError> {
    ensure_supported_platform().map_err(|error| CliError::Operation(error.to_string()))?;
    let content = generate(&options.root, &options.catalog)
        .map_err(|error| CliError::Operation(error.to_string()))?;
    let output_path = options.root.join(&options.output);
    match options.mode {
        Mode::Write => write_generated_file(&output_path, &content).map_err(|error| {
            CliError::Operation(format!("write {}: {error}", options.output.display()))
        }),
        Mode::Check => {
            let existing = read_generated_file(&output_path).map_err(|error| {
                CliError::Operation(format!("read {}: {error}", options.output.display()))
            })?;
            if trim_ascii(&existing) != trim_ascii(&content) {
                return Err(CliError::Stale(options.output.clone()));
            }
            Ok(())
        }
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<ParseResult, CliError> {
    let mut root = PathBuf::from(".");
    let mut catalog = PathBuf::from(DEFAULT_CATALOG_PATH);
    let mut output = PathBuf::from(DEFAULT_OUTPUT_PATH);
    let mut mode = None;
    let mut args = args.peekable();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--root" => root = PathBuf::from(value(&mut args, "--root")?),
            "--catalog" => catalog = PathBuf::from(value(&mut args, "--catalog")?),
            "--output" => output = PathBuf::from(value(&mut args, "--output")?),
            "--write" => set_mode(&mut mode, Mode::Write)?,
            "--check" => set_mode(&mut mode, Mode::Check)?,
            "-h" | "--help" => return Ok(ParseResult::Help),
            _ => return Err(CliError::UnknownArgument(argument)),
        }
    }
    Ok(ParseResult::Run(Options {
        root,
        catalog,
        output,
        mode: mode.ok_or(CliError::MissingMode)?,
    }))
}

fn set_mode(mode: &mut Option<Mode>, next: Mode) -> Result<(), CliError> {
    match mode {
        Some(current) if *current != next => Err(CliError::ConflictingModes),
        Some(_) => Ok(()),
        None => {
            *mode = Some(next);
            Ok(())
        }
    }
}

fn value(args: &mut impl Iterator<Item = String>, flag: &'static str) -> Result<String, CliError> {
    args.next().ok_or(CliError::MissingValue(flag))
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &value[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<ParseResult, CliError> {
        parse_args(args.iter().map(|argument| (*argument).to_owned()))
    }

    #[test]
    fn requires_exactly_one_distinct_mode() {
        assert_eq!(parse(&[]), Err(CliError::MissingMode));
        assert_eq!(
            parse(&["--write", "--check"]),
            Err(CliError::ConflictingModes)
        );
        assert_eq!(
            parse(&["--check", "--write"]),
            Err(CliError::ConflictingModes)
        );

        let Ok(ParseResult::Run(options)) = parse(&["--check", "--check"]) else {
            panic!("repeated mode should parse");
        };
        assert_eq!(options.mode, Mode::Check);
    }

    #[test]
    fn help_is_a_successful_parse_result() {
        assert_eq!(parse(&["--help"]), Ok(ParseResult::Help));
        assert_eq!(parse(&["-h"]), Ok(ParseResult::Help));
    }

    #[test]
    fn parses_paths_and_mode() {
        let Ok(ParseResult::Run(options)) = parse(&[
            "--root",
            "repo",
            "--catalog",
            "catalog.yaml",
            "--output",
            "registry.go",
            "--write",
        ]) else {
            panic!("valid arguments should parse");
        };
        assert_eq!(options.root, PathBuf::from("repo"));
        assert_eq!(options.catalog, PathBuf::from("catalog.yaml"));
        assert_eq!(options.output, PathBuf::from("registry.go"));
        assert_eq!(options.mode, Mode::Write);
    }
}
