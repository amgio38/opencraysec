//! Finding out which runtime products are installed, and at what version.
//!
//! The commands come from a fixed table in this file, never from downloaded data: the lifecycle
//! feed carries free-text "version commands" (pipelines, `cat /etc/os-release`), and running text
//! that arrived over the network would be a hole. Each command is spawned directly (no shell),
//! with no stdin, a short time limit and a cap on how much output is read.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use regex::Regex;

use crate::Input;

/// A product that can be detected, and the one command that prints its version.
pub struct Detector {
    /// The product's slug in the lifecycle feed.
    pub product: &'static str,
    /// Program and arguments (the program is looked up on `PATH`).
    pub argv: &'static [&'static str],
}

/// What `scan_runtime` looks for. PHP appears twice because the command line and PHP-FPM are
/// separate binaries that can be on different versions.
pub const DETECTORS: &[Detector] = &[
    Detector {
        product: "php",
        argv: &["php", "--version"],
    },
    Detector {
        product: "php",
        argv: &["php-fpm", "-v"],
    },
    Detector {
        product: "nginx",
        argv: &["nginx", "-v"],
    },
    Detector {
        product: "apache-http-server",
        argv: &["httpd", "-v"],
    },
    Detector {
        product: "apache-http-server",
        argv: &["apache2", "-v"],
    },
    Detector {
        product: "nodejs",
        argv: &["node", "--version"],
    },
    Detector {
        product: "python",
        argv: &["python3", "--version"],
    },
    Detector {
        product: "go",
        argv: &["go", "version"],
    },
    Detector {
        product: "ruby",
        argv: &["ruby", "--version"],
    },
    Detector {
        product: "rust",
        argv: &["rustc", "--version"],
    },
    Detector {
        product: "perl",
        argv: &["perl", "-v"],
    },
    Detector {
        product: "composer",
        argv: &["composer", "--version"],
    },
    Detector {
        product: "mysql",
        argv: &["mysqld", "--version"],
    },
    Detector {
        product: "mariadb",
        argv: &["mariadbd", "--version"],
    },
    Detector {
        product: "postgresql",
        argv: &["psql", "--version"],
    },
    Detector {
        product: "redis",
        argv: &["redis-server", "--version"],
    },
    Detector {
        product: "mongodb",
        argv: &["mongod", "--version"],
    },
    Detector {
        product: "sqlite",
        argv: &["sqlite3", "--version"],
    },
    Detector {
        product: "haproxy",
        argv: &["haproxy", "-v"],
    },
    Detector {
        product: "openssl",
        argv: &["openssl", "version"],
    },
];

/// How long a version command may run.
const TIMEOUT: Duration = Duration::from_secs(5);
/// How much of a command's output is read.
const MAX_OUTPUT: u64 = 16 * 1024;

fn version_pattern() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[0-9]+(?:\.[0-9]+)+").ok())
        .as_ref()
}

/// The first dotted number in a command's output (`PHP 7.4.33 (cli)` gives `7.4.33`).
pub fn extract_version(output: &str) -> Option<String> {
    version_pattern()?
        .find(output)
        .map(|m| m.as_str().to_string())
}

/// Runs `argv` and returns the first dotted number it prints on stdout or stderr (`nginx -v`
/// writes to stderr). `None` when the program is missing, fails to start, times out or prints
/// no version.
pub fn run_version(argv: &[&str]) -> Option<String> {
    let (program, args) = argv.split_first()?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let read = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(p) = pipe {
                let _ = p.take(MAX_OUTPUT).read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = read(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = read(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(15)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
    let mut text = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&err.join().unwrap_or_default()));
    extract_version(&text)
}

/// Runs every detector. Programs that are not installed are skipped silently; the second value
/// is how many detectors found a program, so a report can say what was looked at.
pub fn detect_all() -> (Vec<Input>, usize) {
    let mut found: Vec<Input> = Vec::new();
    for d in DETECTORS {
        if let Some(version) = run_version(d.argv) {
            let source = format!("detected: {}", d.argv.join(" "));
            // The same product on the same version from two binaries is one fact.
            if !found
                .iter()
                .any(|f| f.product == d.product && f.version == version)
            {
                found.push(Input {
                    product: d.product.to_string(),
                    version,
                    source,
                });
            }
        }
    }
    let n = found.len();
    (found, n)
}

/// Parses a `product@version` argument (`php@7.4.33`).
pub fn parse_given(arg: &str) -> Result<Input, String> {
    let (product, version) = arg
        .split_once('@')
        .ok_or_else(|| format!("{arg:?}: expected product@version, for example php@7.4.33"))?;
    let (product, version) = (product.trim(), version.trim().trim_start_matches('v'));
    let ok_name = !product.is_empty()
        && product
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    let dotted = extract_version(version).is_some_and(|v| v == version);
    let major_only = !version.is_empty() && version.chars().all(|c| c.is_ascii_digit());
    if !ok_name || !(dotted || major_only) {
        return Err(format!(
            "{arg:?}: expected product@version, for example php@7.4.33"
        ));
    }
    Ok(Input {
        product: product.to_string(),
        version: version.to_string(),
        source: "given".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_pulled_out_of_real_command_output() {
        for (out, want) in [
            (
                "PHP 7.4.33 (cli) (built: Dec 18 2025 23:34:54) ( NTS )",
                "7.4.33",
            ),
            ("nginx version: nginx/1.24.0 (Ubuntu)", "1.24.0"),
            ("v22.11.0", "22.11.0"),
            ("Python 3.12.3", "3.12.3"),
            ("go version go1.22.3 linux/amd64", "1.22.3"),
            ("psql (PostgreSQL) 16.2 (Debian 16.2-1.pgdg120+2)", "16.2"),
            (
                "Redis server v=7.0.15 sha=00000000:0 malloc=jemalloc-5.3.0",
                "7.0.15",
            ),
            (
                "This is perl 5, version 36, subversion 0 (v5.36.0) built for x86_64-linux",
                "5.36.0",
            ),
            (
                "mariadbd  Ver 10.11.6-MariaDB-0+deb12u1 for debian-linux-gnu",
                "10.11.6",
            ),
            (
                "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)",
                "3.0.13",
            ),
        ] {
            assert_eq!(extract_version(out).as_deref(), Some(want), "{out}");
        }
        assert_eq!(extract_version("no digits here"), None);
        assert_eq!(
            extract_version("version 8"),
            None,
            "a bare integer is not a version"
        );
    }

    #[test]
    fn a_missing_program_is_not_an_error() {
        assert_eq!(
            run_version(&["opencraysec-no-such-binary-xyz", "--version"]),
            None
        );
        assert_eq!(run_version(&[]), None);
    }

    #[test]
    fn a_real_program_is_read_from_stdout_and_stderr() {
        // `sh -c` is only used by the test to stand in for a program that prints a version.
        assert_eq!(
            run_version(&["sh", "-c", "echo 'tool 1.2.3'"]).as_deref(),
            Some("1.2.3")
        );
        assert_eq!(
            run_version(&["sh", "-c", "echo 'tool 4.5.6' >&2"]).as_deref(),
            Some("4.5.6")
        );
    }

    #[test]
    fn the_detector_table_is_sane() {
        for d in DETECTORS {
            assert!(!d.argv.is_empty());
            assert!(
                !d.argv[0].contains('/') && !d.argv[0].contains(' '),
                "{}: programs come from PATH, bare names only",
                d.argv[0]
            );
        }
    }

    #[test]
    fn given_products_are_parsed_strictly() {
        let i = parse_given("php@7.4.33").expect("ok");
        assert_eq!(
            (i.product.as_str(), i.version.as_str(), i.source.as_str()),
            ("php", "7.4.33", "given")
        );
        assert_eq!(
            parse_given("nodejs@v22.11.0").expect("v prefix").version,
            "22.11.0"
        );
        assert_eq!(parse_given("nodejs@22").expect("bare major").version, "22");
        for bad in [
            "php",
            "@7.4",
            "php@",
            "ph p@7.4",
            "php@seven",
            "php@7.4.33; rm",
        ] {
            assert!(parse_given(bad).is_err(), "{bad}");
        }
    }
}
