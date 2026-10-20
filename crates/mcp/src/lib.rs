//! MCP server (stdio, newline-delimited JSON-RPC) exposing opencraysec to an AI harness.
//!
//! stdout carries only protocol messages. Tool paths are confined to the workspace root. The
//! server never modifies the project; `update_db` writes only to the advisory data directory.

mod server;
mod tools;

pub use server::{MAX_MESSAGE_BYTES, ServerConfig, serve};

/// Protocol revision spoken.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Name reported in `initialize`.
pub const SERVER_NAME: &str = "opencraysec";
