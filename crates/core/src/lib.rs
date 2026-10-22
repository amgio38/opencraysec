//! Shared types and pure logic for opencraysec: package model, per-ecosystem version
//! ordering, CVSS v3 scoring and OSV advisory matching. No I/O lives here.

pub mod cvss;
pub mod model;
pub mod osv;
pub mod version;

pub use model::{Ecosystem, Finding, Package, Reachability, Severity, is_malicious_id};
