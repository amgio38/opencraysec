//! The opencraysec engine: scan a project, explain an advisory, plan a fix, verify it, and
//! render reports. Both the CLI and the MCP server are thin shells over this crate.

use std::fmt;

pub mod code;
pub mod explain;
pub mod fix;
pub mod reach;
pub mod report;
pub mod scan;

pub use code::{CodeFinding, CodeOptions, CodeReport, scan_code};
pub use explain::{Explanation, explain};
pub use fix::{FixPlan, FixStep, VerifyOutcome, plan_fix, verify_fix};
pub use scan::{DataSource, ScanOptions, ScanReport, scan};

/// Error from the engine.
#[derive(Debug)]
pub struct EngineError(pub String);

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EngineError {}

impl From<opencraysec_db::DbError> for EngineError {
    fn from(e: opencraysec_db::DbError) -> Self {
        EngineError(e.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_display_and_convert_from_the_store() {
        let e = EngineError("boom".into());
        assert_eq!(e.to_string(), "boom");
        let from: EngineError = opencraysec_db::DbError("db down".into()).into();
        assert_eq!(from.0, "db down");
        let boxed: Box<dyn std::error::Error> = Box::new(from);
        assert_eq!(boxed.to_string(), "db down");
    }
}
