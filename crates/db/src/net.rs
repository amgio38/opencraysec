//! Minimal HTTP helpers over `ureq`. The only data that leaves the machine is a URL and, for the
//! online OSV fallback, package names and versions.

use std::io::Read;
use std::time::Duration;

use crate::DbError;

/// Largest single download we accept (bytes).
pub const MAX_DOWNLOAD: u64 = 2 * 1024 * 1024 * 1024;

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(900)))
        .user_agent(concat!("opencraysec/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Opens `url` for streaming.
pub fn open(url: &str) -> Result<Box<dyn Read + Send>, DbError> {
    let resp = agent()
        .get(url)
        .call()
        .map_err(|e| DbError(format!("GET {url}: {e}")))?;
    Ok(Box::new(resp.into_body().into_reader().take(MAX_DOWNLOAD)))
}

/// GETs `url` fully into memory (up to `limit` bytes).
pub fn get_bytes(url: &str, limit: u64) -> Result<Vec<u8>, DbError> {
    let resp = agent()
        .get(url)
        .call()
        .map_err(|e| DbError(format!("GET {url}: {e}")))?;
    resp.into_body()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| DbError(format!("GET {url}: {e}")))
}

/// POSTs a JSON body and returns the response bytes.
pub fn post_json(url: &str, body: &serde_json::Value, limit: u64) -> Result<Vec<u8>, DbError> {
    let resp = agent()
        .post(url)
        .header("content-type", "application/json")
        .send(body.to_string())
        .map_err(|e| DbError(format!("POST {url}: {e}")))?;
    resp.into_body()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| DbError(format!("POST {url}: {e}")))
}

/// GETs `url` with extra request headers.
pub fn get_bytes_with_headers(
    url: &str,
    headers: &[(&str, &str)],
    limit: u64,
) -> Result<Vec<u8>, DbError> {
    let mut req = agent().get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.call().map_err(|e| DbError(format!("GET {url}: {e}")))?;
    resp.into_body()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| DbError(format!("GET {url}: {e}")))
}
