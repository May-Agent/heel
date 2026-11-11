//! `heel-shim`: the executable a sandboxed process runs to call a host command.
//!
//! Reporting results to the terminal is this binary's purpose, so the
//! workspace lints against printing are lifted here.
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::process::ExitCode;

mod args;
mod error;
mod invoke;
mod native;

fn main() -> ExitCode {
    match native::parse().and_then(invoke::execute) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
