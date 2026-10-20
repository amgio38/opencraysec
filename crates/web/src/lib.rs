//! The report dashboard: a small read-only HTTP server over the activity log, and a single-file
//! HTML export of the same report.
//!
//! The server only answers `GET`. Everything it shows comes from the local log. Text from
//! advisories is third-party data, so the page inserts it with `textContent` only, and responses
//! carry a restrictive Content-Security-Policy.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use opencraysec_log::EventLog;
use opencraysec_log::summary::summarize;

const INDEX: &str = include_str!("assets/index.html");
const CSS: &str = include_str!("assets/app.css");
const JS: &str = include_str!("assets/app.js");

/// Chart.js is loaded from a CDN at a pinned version and checked with SRI; the page falls back to
/// tables when it cannot be loaded.
const CHART_SRC: &str = "https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.js";
const CHART_SRI: &str = "sha384-zYPBGXwO4633CABX/5Spf6emCKUJCfoOkhOMYyxMsatqQZPnDblmmOewfjsIVWCM";

/// The default port of the dashboard.
pub const DEFAULT_PORT: u16 = 1787;
/// The default bind address.
pub const DEFAULT_HOST: &str = "0.0.0.0";

const MAX_REQUEST_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_CONNECTIONS: usize = 64;

/// What the server needs to answer requests.
#[derive(Clone)]
pub struct WebConfig {
    /// The activity log to report on.
    pub log: EventLog,
    /// When set, every request except `/healthz` and the page's own static assets must carry it
    /// (`?token=` or `Authorization: Bearer`).
    pub token: Option<String>,
}

/// A response ready to be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// `Content-Type` value.
    pub content_type: &'static str,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl Response {
    fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }
}

fn head_block() -> String {
    format!(
        "<link rel=\"stylesheet\" href=\"/app.css\">\n<script src=\"{CHART_SRC}\" integrity=\"{CHART_SRI}\" crossorigin=\"anonymous\" defer></script>"
    )
}

/// The page served at `/`: styles and script are separate files so the CSP needs no `unsafe-inline`.
pub fn index_html() -> String {
    INDEX
        .replace("{{HEAD}}", &head_block())
        .replace("{{EMBED}}", "")
        .replace("{{SCRIPT}}", "<script src=\"/app.js\" defer></script>")
}

/// A self-contained report for one project (everything inlined; only Chart.js comes from the CDN).
pub fn report_html(log: &EventLog, workspace: Option<&str>) -> String {
    let summary = summarize(&log.read_all(), workspace);
    // `<` is escaped so the data cannot close the script element.
    let data = summary.to_string().replace('<', "\\u003c");
    let head = format!(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline'; connect-src 'none'; img-src data:\">\n<style>{CSS}</style>\n<script src=\"{CHART_SRC}\" integrity=\"{CHART_SRI}\" crossorigin=\"anonymous\" defer></script>"
    );
    INDEX
        .replace("{{HEAD}}", &head)
        .replace(
            "{{EMBED}}",
            &format!("<script type=\"application/json\" id=\"embedded-data\">{data}</script>"),
        )
        .replace("{{SCRIPT}}", &format!("<script>{JS}</script>"))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (percent_decode(k) == key).then(|| percent_decode(v))
    })
}

/// The two files every page needs; they hold no data from the activity log.
fn static_asset(path: &str) -> Option<Response> {
    let (content_type, body) = match path {
        "/app.css" => ("text/css; charset=utf-8", CSS),
        "/app.js" => ("text/javascript; charset=utf-8", JS),
        _ => return None,
    };
    Some(Response {
        status: 200,
        content_type,
        body: body.as_bytes().to_vec(),
    })
}

/// Answers one request. `authorization` is the raw `Authorization` header value, if any.
pub fn route(cfg: &WebConfig, method: &str, target: &str, authorization: Option<&str>) -> Response {
    if method != "GET" {
        return Response::text(405, "read-only: only GET is supported");
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path == "/healthz" {
        return Response::text(200, "ok");
    }
    // The page's own stylesheet and script are compile-time constants with no user data. A browser
    // fetches them without the page's query string, so gating them would leave a token-protected
    // dashboard stuck on "Loading". Everything that reads the activity log stays behind the token.
    if let Some(asset) = static_asset(path) {
        return asset;
    }
    if let Some(expected) = &cfg.token {
        let given = query_param(query, "token").or_else(|| {
            authorization
                .and_then(|a| a.strip_prefix("Bearer "))
                .map(str::to_string)
        });
        if !given.is_some_and(|g| constant_time_eq(&g, expected)) {
            return Response::text(
                401,
                "a token is required: open the dashboard with ?token=<token>",
            );
        }
    }
    match path {
        "/" | "/index.html" => Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: index_html().into_bytes(),
        },
        "/api/summary" => {
            let ws = query_param(query, "workspace");
            let body = summarize(&cfg.log.read_all(), ws.as_deref()).to_string();
            Response {
                status: 200,
                content_type: "application/json; charset=utf-8",
                body: body.into_bytes(),
            }
        }
        _ => Response::text(404, "not found"),
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    }
}

fn write_response(stream: &mut TcpStream, r: &Response) -> io::Result<()> {
    let csp = "default-src 'none'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: {csp}\r\nConnection: close\r\n\r\n",
        r.status,
        status_text(r.status),
        r.content_type,
        r.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&r.body)
}

fn handle(mut stream: TcpStream, cfg: &WebConfig) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone.take(MAX_REQUEST_LINE as u64 * 4));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.len() > MAX_REQUEST_LINE {
        let _ = write_response(&mut stream, &Response::text(400, "bad request"));
        return;
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        let _ = write_response(&mut stream, &Response::text(400, "bad request"));
        return;
    };
    let (method, target) = (method.to_string(), target.to_string());
    let mut authorization = None;
    for _ in 0..MAX_HEADERS {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':')
            && k.eq_ignore_ascii_case("authorization")
        {
            authorization = Some(v.trim().to_string());
        }
    }
    let resp = route(cfg, &method, &target, authorization.as_deref());
    let _ = write_response(&mut stream, &resp);
}

/// Binds the listening socket.
pub fn bind(host: &str, port: u16) -> io::Result<TcpListener> {
    let addr = (host, port).to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot resolve the bind address",
        )
    })?;
    TcpListener::bind(addr)
}

/// Serves requests on `listener`. Stops after `max_requests` connections when given (tests);
/// otherwise runs until the process ends.
pub fn serve_listener(
    listener: TcpListener,
    cfg: WebConfig,
    max_requests: Option<usize>,
) -> io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    let mut served = 0usize;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            let mut s = stream;
            let _ = write_response(&mut s, &Response::text(400, "busy"));
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (cfg, active_c) = (cfg.clone(), active.clone());
        let worker = std::thread::spawn(move || {
            handle(stream, &cfg);
            active_c.fetch_sub(1, Ordering::SeqCst);
        });
        served += 1;
        if max_requests.is_some_and(|m| served >= m) {
            let _ = worker.join();
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencraysec_log::Event;
    use serde_json::json;

    fn cfg_with_data(dir: &std::path::Path, token: Option<&str>) -> WebConfig {
        let log = EventLog::at(dir.join("log"));
        log.append(&Event::new(
            "scan",
            "/proj",
            Some("claude-code"),
            json!({"total": 1, "by_severity": {"high": 1}, "findings": [{"id": "G1", "package": "<img src=x onerror=alert(1)>", "severity": "high"}]}),
        ))
        .expect("append");
        WebConfig {
            log,
            token: token.map(str::to_string),
        }
    }

    fn body(r: &Response) -> String {
        String::from_utf8(r.body.clone()).expect("utf8")
    }

    #[test]
    fn serves_pages_assets_and_api() {
        let dir = tempfile::tempdir().expect("tmp");
        let cfg = cfg_with_data(dir.path(), None);
        let index = route(&cfg, "GET", "/", None);
        assert_eq!(
            (index.status, index.content_type),
            (200, "text/html; charset=utf-8")
        );
        let html = body(&index);
        assert!(html.contains("/app.js") && html.contains("integrity=\"sha384-"));
        assert!(!html.contains("{{"), "all placeholders are filled");
        assert_eq!(
            route(&cfg, "GET", "/app.css", None).content_type,
            "text/css; charset=utf-8"
        );
        assert!(body(&route(&cfg, "GET", "/app.js", None)).contains("textContent"));
        let api = route(&cfg, "GET", "/api/summary?workspace=%2Fproj", None);
        let v: serde_json::Value = serde_json::from_str(&body(&api)).expect("json");
        assert_eq!(v["workspace"], "/proj");
        assert_eq!(v["kpis"]["open"], 1);
        assert_eq!(route(&cfg, "GET", "/healthz", None).status, 200);
        assert_eq!(route(&cfg, "GET", "/nope", None).status, 404);
        assert_eq!(route(&cfg, "POST", "/", None).status, 405);
    }

    #[test]
    fn token_protects_the_page_and_the_data() {
        let dir = tempfile::tempdir().expect("tmp");
        let cfg = cfg_with_data(dir.path(), Some("s3cret"));
        assert_eq!(route(&cfg, "GET", "/", None).status, 401);
        assert_eq!(route(&cfg, "GET", "/api/summary", None).status, 401);
        assert_eq!(route(&cfg, "GET", "/?token=wrong", None).status, 401);
        assert_eq!(route(&cfg, "GET", "/?token=s3cret", None).status, 200);
        assert_eq!(
            route(&cfg, "GET", "/api/summary?token=s3cret", None).status,
            200
        );
        assert_eq!(
            route(&cfg, "GET", "/api/summary", Some("Bearer s3cret")).status,
            200
        );
        assert_eq!(
            route(&cfg, "GET", "/api/summary", Some("Basic s3cret")).status,
            401
        );
        assert_eq!(route(&cfg, "GET", "/healthz", None).status, 200);
    }

    #[test]
    fn a_token_protected_page_can_still_load_its_own_assets() {
        let dir = tempfile::tempdir().expect("tmp");
        let cfg = cfg_with_data(dir.path(), Some("s3cret"));
        // The browser requests these without the page's `?token=`.
        let css = route(&cfg, "GET", "/app.css", None);
        let js = route(&cfg, "GET", "/app.js", None);
        assert_eq!((css.status, js.status), (200, 200));
        assert!(body(&js).contains("textContent"));
        assert_eq!(route(&cfg, "GET", "/api/summary", None).status, 401);
        assert_eq!(route(&cfg, "GET", "/", None).status, 401);
    }

    #[test]
    fn export_inlines_everything_and_cannot_be_broken_out_of() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut cfg = cfg_with_data(dir.path(), None);
        cfg.log
            .append(&Event::new("scan", "/proj", None, json!({"total": 0, "findings": [], "notes": ["</script><script>alert(1)</script>"]})))
            .expect("append");
        let html = report_html(&cfg.log, Some("/proj"));
        assert!(html.contains("id=\"embedded-data\""));
        assert!(html.contains("<style>") && html.contains("textContent"));
        assert!(!html.contains("{{"));
        let data_start = html.find("id=\"embedded-data\"").expect("data");
        let data_end = html[data_start..].find("</script>").expect("end") + data_start;
        assert!(
            !html[data_start..data_end].contains("<script>"),
            "'<' is escaped inside the data block"
        );
        assert!(html.contains("\\u003c/script>"));
        cfg.token = None;
        let empty = report_html(&EventLog::at(dir.path().join("none")), None);
        assert!(empty.contains("\"empty\":true"));
    }

    #[test]
    fn query_parsing_and_decoding() {
        assert_eq!(percent_decode("%2Fa%20b+c%zz%4"), "/a b c%zz%4");
        assert_eq!(
            query_param("a=1&workspace=%2Fp&token=t", "workspace").as_deref(),
            Some("/p")
        );
        assert_eq!(query_param("a=1", "b"), None);
        assert!(
            constant_time_eq("abc", "abc")
                && !constant_time_eq("abc", "abd")
                && !constant_time_eq("abc", "ab")
        );
    }

    #[test]
    fn real_socket_roundtrip_and_limits() {
        let dir = tempfile::tempdir().expect("tmp");
        let cfg = cfg_with_data(dir.path(), None);
        let listener = bind("127.0.0.1", 0).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || serve_listener(listener, cfg, Some(3)));

        let ask = |req: &str| {
            let mut s = TcpStream::connect(addr).expect("connect");
            s.write_all(req.as_bytes()).expect("write");
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        };
        let ok = ask("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(ok.starts_with("HTTP/1.1 200 OK"));
        assert!(
            ok.contains("Content-Security-Policy:")
                && ok.contains("X-Frame-Options: DENY")
                && ok.contains("Cache-Control: no-store")
        );
        let bad = ask("garbage\r\n\r\n");
        assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
        let post = ask("POST /api/summary HTTP/1.1\r\nAuthorization: Bearer x\r\n\r\n");
        assert!(post.starts_with("HTTP/1.1 405"));
        server.join().expect("thread").expect("serve");
    }
}
