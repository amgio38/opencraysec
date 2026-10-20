//! Downloads the OSV ecosystem dumps, the CISA KEV list and the EPSS scores.

use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use flate2::read::GzDecoder;
use opencraysec_core::Ecosystem;
use opencraysec_core::osv::{OsvRecord, trim_ecosystem_specific};

use crate::{DbError, EcoMeta, Store, encode_line, net, now_rfc3339};

pub use crate::cwe::update_cwe;

/// Advisory descriptions are cut to this many characters when stored.
const MAX_DETAILS: usize = 4000;

/// Converts an OSV zip into the store's JSONL format. Returns the number of records written.
pub fn ingest_zip(eco: Ecosystem, zip_path: &Path, out_path: &Path) -> Result<usize, DbError> {
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| DbError(format!("bad zip: {e}")))?;
    let mut out = BufWriter::new(fs::File::create(out_path)?);
    let mut count = 0;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| DbError(format!("bad zip entry: {e}")))?;
        if !entry.name().is_ok_and(|n| n.ends_with(".json")) {
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size().min(1 << 20) as usize);
        io::Read::read_to_end(&mut entry, &mut buf)?;
        let Ok(mut rec) = serde_json::from_slice::<OsvRecord>(&buf) else {
            continue;
        };
        if rec.withdrawn.is_some() {
            continue;
        }
        for a in &mut rec.affected {
            a.ecosystem_specific = trim_ecosystem_specific(a.ecosystem_specific.take());
        }
        if let Some(d) = &mut rec.details
            && d.chars().count() > MAX_DETAILS
        {
            *d = d.chars().take(MAX_DETAILS).collect();
        }
        if let Some(line) = encode_line(eco, &rec)? {
            out.write_all(line.as_bytes())?;
            out.write_all(b"\n")?;
            count += 1;
        }
    }
    out.flush()?;
    Ok(count)
}

/// Downloads and installs the advisories for one ecosystem.
pub fn update_osv(store: &Store, eco: Ecosystem) -> Result<EcoMeta, DbError> {
    fs::create_dir_all(store.osv_dir())?;
    let zip_path = store.osv_dir().join(format!("{}.zip.tmp", eco.osv_name()));
    let url = format!("{}/{}/all.zip", store.endpoints().osv_dump, eco.osv_name());
    {
        let mut reader = net::open(&url)?;
        let mut f = BufWriter::new(fs::File::create(&zip_path)?);
        io::copy(&mut reader, &mut f)?;
        f.flush()?;
    }
    let tmp = store.jsonl_path(eco).with_extension("jsonl.tmp");
    let result = ingest_zip(eco, &zip_path, &tmp);
    let _ = fs::remove_file(&zip_path);
    let records = match result {
        Ok(n) => n,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    };
    fs::rename(&tmp, store.jsonl_path(eco))?;
    let meta = EcoMeta {
        updated_at: now_rfc3339(),
        records,
        schema: crate::SCHEMA,
    };
    store.write_atomic(
        &store.meta_path(eco),
        serde_json::to_string(&meta)?.as_bytes(),
    )?;
    Ok(meta)
}

/// Extracts the CVE ids from a CISA KEV feed.
pub fn parse_kev(json: &[u8]) -> Result<Vec<String>, DbError> {
    let v: serde_json::Value = serde_json::from_slice(json)?;
    let list = v
        .get("vulnerabilities")
        .and_then(|x| x.as_array())
        .ok_or_else(|| DbError("KEV feed has no `vulnerabilities` array".into()))?;
    Ok(list
        .iter()
        .filter_map(|e| e.get("cveID").and_then(|x| x.as_str()).map(str::to_string))
        .collect())
}

/// Fetches the CISA Known Exploited Vulnerabilities list. Returns the number of ids.
pub fn update_kev(store: &Store) -> Result<usize, DbError> {
    let bytes = net::get_bytes(&store.endpoints().kev, 64 * 1024 * 1024)?;
    let ids = parse_kev(&bytes)?;
    let doc = serde_json::json!({ "updated_at": now_rfc3339(), "ids": ids });
    store.write_atomic(&store.kev_path(), doc.to_string().as_bytes())?;
    Ok(ids.len())
}

/// Converts an EPSS CSV stream (`cve,epss,percentile`) to `CVE<TAB>score` lines.
pub fn convert_epss(csv: impl BufRead, out: &mut impl Write) -> Result<usize, DbError> {
    let mut n = 0;
    for line in csv.lines() {
        let line = line?;
        let mut it = line.split(',');
        if let (Some(id), Some(score)) = (it.next(), it.next())
            && id.starts_with("CVE-")
            && score.parse::<f32>().is_ok()
        {
            writeln!(out, "{id}\t{score}")?;
            n += 1;
        }
    }
    Ok(n)
}

/// Fetches the EPSS scores. Returns the number of CVEs scored.
pub fn update_epss(store: &Store) -> Result<usize, DbError> {
    let reader = net::open(&store.endpoints().epss)?;
    let mut out = Vec::new();
    writeln!(out, "#updated_at={}", now_rfc3339())?;
    let n = convert_epss(BufReader::new(GzDecoder::new(reader)), &mut out)?;
    store.write_atomic(&store.epss_path(), &out)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kev_parsing() {
        let ids = parse_kev(br#"{"vulnerabilities":[{"cveID":"CVE-1"},{"cveID":"CVE-2"},{}]}"#)
            .expect("parses");
        assert_eq!(ids, vec!["CVE-1", "CVE-2"]);
        assert!(parse_kev(b"{}").is_err());
    }

    #[test]
    fn epss_conversion() {
        let csv =
            "#model_version:v1,score_date:x\ncve,epss,percentile\nCVE-2026-1,0.0123,0.5\nbad,1,1\n";
        let mut out = Vec::new();
        let n = convert_epss(csv.as_bytes(), &mut out).expect("converts");
        assert_eq!(n, 1);
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "CVE-2026-1\t0.0123\n"
        );
    }

    #[test]
    fn zip_ingest_keeps_matching_non_withdrawn() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().expect("tmp");
        let zp = dir.path().join("a.zip");
        {
            let mut z = zip::ZipWriter::new(fs::File::create(&zp).expect("create"));
            let opts = zip::write::SimpleFileOptions::default();
            for (name, body) in [
                (
                    "A.json",
                    r#"{"id":"A","affected":[{"package":{"ecosystem":"Go","name":"m"}}]}"#,
                ),
                (
                    "B.json",
                    r#"{"id":"B","withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"m"}}]}"#,
                ),
                (
                    "C.json",
                    r#"{"id":"C","affected":[{"package":{"ecosystem":"npm","name":"m"}}]}"#,
                ),
                ("readme.txt", "x"),
            ] {
                z.start_file(name, opts).expect("start");
                z.write_all(body.as_bytes()).expect("write");
            }
            z.finish().expect("finish");
        }
        let out = dir.path().join("o.jsonl");
        assert_eq!(ingest_zip(Ecosystem::Go, &zp, &out).expect("ingest"), 1);
        assert!(
            fs::read_to_string(&out)
                .expect("read")
                .contains("\"id\":\"A\"")
        );
    }
}
