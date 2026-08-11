use hp_guard::{simulate_trace, SimulationPolicy};
use serde_json::json;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

struct Arguments {
    policy: PathBuf,
    trace: PathBuf,
    compare: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        let line = error.line;
        eprintln!("{}", json!({"code": error.code, "line": line}));
        std::process::exit(1);
    }
}

struct CliError {
    code: &'static str,
    line: Option<usize>,
}

fn run() -> Result<(), CliError> {
    let arguments = parse_arguments(env::args().skip(1))?;
    let baseline_text = read_file(&arguments.policy)?;
    let trace = read_file(&arguments.trace)?;
    let baseline = SimulationPolicy::parse(&baseline_text).map_err(|error| CliError {
        code: error.code(),
        line: None,
    })?;
    let candidate_text = arguments.compare.as_ref().map(read_file).transpose()?;
    let candidate = candidate_text
        .as_deref()
        .map(SimulationPolicy::parse)
        .transpose()
        .map_err(|error| CliError {
            code: error.code(),
            line: None,
        })?;
    let reports =
        simulate_trace(&baseline, candidate.as_ref(), &trace).map_err(|error| CliError {
            code: error.code(),
            line: Some(error.line_number()),
        })?;
    let output = reports
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CliError {
            code: "serialization_error",
            line: None,
        })?
        .join("\n");
    if !output.is_empty() {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(output.as_bytes())
            .and_then(|_| stdout.write_all(b"\n"))
            .map_err(|_| CliError {
                code: "io_error",
                line: None,
            })?;
    }
    Ok(())
}

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Arguments, CliError> {
    let mut policy = None;
    let mut trace = None;
    let mut compare = None;
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or(CliError {
            code: "invalid_arguments",
            line: None,
        })?;
        match argument.as_str() {
            "--policy" if policy.is_none() => policy = Some(PathBuf::from(value)),
            "--trace" if trace.is_none() => trace = Some(PathBuf::from(value)),
            "--compare" if compare.is_none() => compare = Some(PathBuf::from(value)),
            _ => {
                return Err(CliError {
                    code: "invalid_arguments",
                    line: None,
                });
            }
        }
    }
    Ok(Arguments {
        policy: policy.ok_or(CliError {
            code: "invalid_arguments",
            line: None,
        })?,
        trace: trace.ok_or(CliError {
            code: "invalid_arguments",
            line: None,
        })?,
        compare,
    })
}

fn read_file(path: &PathBuf) -> Result<String, CliError> {
    fs::read_to_string(path).map_err(|_| CliError {
        code: "io_error",
        line: None,
    })
}
