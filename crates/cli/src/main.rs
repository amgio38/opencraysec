//! `opencraysec` binary.

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = opencraysec_cli::run(
        std::env::args(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(code)
}
