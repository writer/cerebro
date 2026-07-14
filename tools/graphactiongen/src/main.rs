use cerebro_graphactiongen::{
    DEFAULT_CATALOG_PATH, DEFAULT_OUTPUT_PATH, generate, read_generated_file, write_generated_file,
};
use std::env;
use std::path::PathBuf;

#[derive(Debug)]
struct Options {
    root: PathBuf,
    catalog: PathBuf,
    output: PathBuf,
    write: bool,
    check: bool,
}

fn main() {
    let options = match parse_args(env::args().skip(1)) {
        Ok(options) if options.write || options.check => options,
        Ok(_) => {
            eprintln!("graphactiongen: one of --write or --check is required");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("graphactiongen: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(&options) {
        eprintln!("graphactiongen: {error}");
        std::process::exit(1);
    }
}

fn run(options: &Options) -> Result<(), String> {
    let content = generate(&options.root, &options.catalog)?;
    let output_path = options.root.join(&options.output);
    if options.write {
        write_generated_file(&output_path, &content)
            .map_err(|err| format!("write {}: {err}", options.output.display()))?;
    }
    if options.check {
        let existing = read_generated_file(&output_path)
            .map_err(|err| format!("read {}: {err}", options.output.display()))?;
        if trim_ascii(&existing) != trim_ascii(&content) {
            return Err(format!(
                "{} is stale; run `make graph-action-generate`",
                options.output.display()
            ));
        }
    }
    Ok(())
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        root: PathBuf::from("."),
        catalog: PathBuf::from(DEFAULT_CATALOG_PATH),
        output: PathBuf::from(DEFAULT_OUTPUT_PATH),
        write: false,
        check: false,
    };
    let mut args = args.peekable();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--root" => options.root = PathBuf::from(value(&mut args, "--root")?),
            "--catalog" => options.catalog = PathBuf::from(value(&mut args, "--catalog")?),
            "--output" => options.output = PathBuf::from(value(&mut args, "--output")?),
            "--write" => options.write = true,
            "--check" => options.check = true,
            "-h" | "--help" => return Err("usage: graphactiongen [--root PATH] [--catalog PATH] [--output PATH] (--write|--check)".to_owned()),
            _ => return Err(format!("unknown argument {argument:?}")),
        }
    }
    Ok(options)
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
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
