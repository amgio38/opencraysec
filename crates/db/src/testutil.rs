//! A tiny HTTP server for tests: canned responses by method and path, with request recording.
#![allow(clippy::expect_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// One canned response.
#[derive(Clone)]
pub struct Route {
    /// `GET` or `POST`.
    pub method: &'static str,
    /// Request target including any query string.
    pub path: String,
    /// HTTP status.
    pub status: u16,
    /// Response body (the first answer).
    pub body: Vec<u8>,
    /// Later answers, used one per further request; the last one repeats.
    pub then: Vec<Vec<u8>>,
}

/// A running mock server; it stops when dropped.
pub struct MockServer {
    /// `http://127.0.0.1:<port>`.
    pub base: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Route {
    /// Adds answers for the second and later requests to this route.
    pub fn then(mut self, body: impl Into<Vec<u8>>) -> Route {
        self.then.push(body.into());
        self
    }

    /// A 200 GET route.
    pub fn get(path: &str, body: impl Into<Vec<u8>>) -> Route {
        Route {
            method: "GET",
            path: path.into(),
            status: 200,
            body: body.into(),
            then: vec![],
        }
    }

    /// A 200 POST route.
    pub fn post(path: &str, body: impl Into<Vec<u8>>) -> Route {
        Route {
            method: "POST",
            path: path.into(),
            status: 200,
            body: body.into(),
            then: vec![],
        }
    }
}

fn handle(mut stream: TcpStream, routes: &[Route], hits: &mut [usize], log: &Mutex<Vec<String>>) {
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    );
    let mut length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length];
    let _ = reader.read_exact(&mut body);
    if let Ok(mut l) = log.lock() {
        l.push(format!(
            "{method} {path} {}",
            String::from_utf8_lossy(&body)
        ));
    }
    let found = routes
        .iter()
        .position(|r| r.method == method && r.path == path);
    let (status, payload) = match found {
        Some(i) => {
            let r = &routes[i];
            let n = hits[i];
            hits[i] += 1;
            let body = if n == 0 {
                r.body.clone()
            } else {
                r.then
                    .get(n - 1)
                    .or(r.then.last())
                    .cloned()
                    .unwrap_or_else(|| r.body.clone())
            };
            (r.status, body)
        }
        None => (404, b"not found".to_vec()),
    };
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&payload);
}

impl MockServer {
    /// Starts a server on a free local port.
    pub fn start(routes: Vec<Route>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, flag) = (requests.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            let mut hits = vec![0usize; routes.len()];
            for stream in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(s) = stream {
                    handle(s, &routes, &mut hits, &log);
                }
            }
        });
        MockServer {
            base,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    /// `METHOD path body` lines for every request received so far.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.base.trim_start_matches("http://"));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
