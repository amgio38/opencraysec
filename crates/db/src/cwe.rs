//! The MITRE CWE catalog: weakness names and descriptions for `explain`.

use std::fs;
use std::io::{BufRead, BufReader, Read};

use crate::{DbError, Store, net, now_rfc3339};

/// One catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CweEntry {
    /// Numeric id (`79` for CWE-79).
    pub id: u32,
    /// Weakness name.
    pub name: String,
    /// Short description.
    pub description: String,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '<' => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = tag.find(&key)? + key.len();
    let end = tag[start..].find('"')? + start;
    Some(&tag[start..end])
}

/// Extracts weaknesses and categories from a `cwec_*.xml` document.
pub fn parse_catalog(xml: &str) -> Vec<CweEntry> {
    let mut out = Vec::new();
    for (open, body_tag) in [("<Weakness ", "Description"), ("<Category ", "Summary")] {
        let mut rest = xml;
        while let Some(i) = rest.find(open) {
            rest = &rest[i + 1..];
            let Some(tag_end) = rest.find('>') else { break };
            let tag = &rest[..tag_end];
            let element_end = rest.find(&open[..open.len() - 1]).unwrap_or(rest.len());
            let next_open = rest[1..].find(open).map_or(rest.len(), |n| n + 1);
            let body = &rest[tag_end..next_open.min(element_end.max(tag_end))];
            let (Some(id), Some(name)) = (attr(tag, "ID"), attr(tag, "Name")) else {
                continue;
            };
            let Ok(id) = id.parse::<u32>() else { continue };
            let open_tag = format!("<{body_tag}>");
            let close_tag = format!("</{body_tag}>");
            let description = body
                .find(&open_tag)
                .and_then(|s| {
                    let s = s + open_tag.len();
                    body[s..]
                        .find(&close_tag)
                        .map(|e| strip_tags(&unescape(&body[s..s + e])))
                })
                .unwrap_or_default();
            out.push(CweEntry {
                id,
                name: unescape(name),
                description,
            });
        }
    }
    out.sort_by_key(|e| e.id);
    out.dedup_by_key(|e| e.id);
    out
}

/// Serialises entries as `#updated_at=...` plus one `id<TAB>name<TAB>description` line each.
pub fn to_tsv(entries: &[CweEntry]) -> String {
    let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    let mut out = format!("#updated_at={}\n", now_rfc3339());
    for e in entries {
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            e.id,
            clean(&e.name),
            clean(&e.description)
        ));
    }
    out
}

/// Downloads the catalog and stores it. Returns the number of entries.
pub fn update_cwe(store: &Store) -> Result<usize, DbError> {
    let bytes = net::get_bytes(&store.endpoints().cwe, 64 * 1024 * 1024)?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| DbError(format!("bad CWE zip: {e}")))?;
    let mut xml = String::new();
    for i in 0..archive.len() {
        let mut f = archive
            .by_index(i)
            .map_err(|e| DbError(format!("bad CWE zip: {e}")))?;
        if f.name().is_ok_and(|n| n.ends_with(".xml")) {
            f.by_ref()
                .take(128 * 1024 * 1024)
                .read_to_string(&mut xml)?;
            break;
        }
    }
    let entries = parse_catalog(&xml);
    if entries.is_empty() {
        return Err(DbError("CWE catalog contained no entries".into()));
    }
    store.write_atomic(&store.cwe_path(), to_tsv(&entries).as_bytes())?;
    Ok(entries.len())
}

impl Store {
    /// Looks up a CWE by numeric id in the downloaded catalog.
    pub fn cwe(&self, id: u32) -> Option<CweEntry> {
        let file = fs::File::open(self.cwe_path()).ok()?;
        let wanted = format!("{id}\t");
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if let Some(rest) = line.strip_prefix(&wanted) {
                let (name, description) = rest.split_once('\t').unwrap_or((rest, ""));
                return Some(CweEntry {
                    id,
                    name: name.to_string(),
                    description: description.to_string(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<Weakness_Catalog><Weaknesses>
      <Weakness ID="79" Name="Improper Neutralization of Input (&apos;XSS&apos;)" Abstraction="Base">
         <Description>The product does not <xhtml:b>neutralize</xhtml:b> input &amp; more.</Description>
         <Extended_Description>long</Extended_Description>
      </Weakness>
      <Weakness ID="20" Name="Improper Input Validation" Abstraction="Class"><Description>Validate.</Description></Weakness>
      </Weaknesses><Categories>
      <Category ID="254" Name="Security Features"><Summary>Security feature weaknesses.</Summary></Category>
      </Categories></Weakness_Catalog>"#;

    #[test]
    fn parses_weaknesses_and_categories() {
        let e = parse_catalog(XML);
        assert_eq!(
            e.iter().map(|x| x.id).collect::<Vec<_>>(),
            vec![20, 79, 254]
        );
        let xss = e.iter().find(|x| x.id == 79).expect("79");
        assert_eq!(xss.name, "Improper Neutralization of Input ('XSS')");
        assert_eq!(
            xss.description,
            "The product does not neutralize input & more."
        );
        assert_eq!(
            e.iter().find(|x| x.id == 20).expect("20").description,
            "Validate."
        );
        assert_eq!(
            e.iter().find(|x| x.id == 254).expect("254").description,
            "Security feature weaknesses."
        );
    }

    #[test]
    fn tsv_roundtrip_through_store() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::at(dir.path());
        assert!(store.cwe(79).is_none());
        store
            .write_atomic(&store.cwe_path(), to_tsv(&parse_catalog(XML)).as_bytes())
            .expect("w");
        let c = store.cwe(79).expect("found");
        assert!(c.name.contains("XSS"));
        assert!(store.cwe(9999).is_none());
        assert!(store.status().cwe_updated_at.is_some());
    }
}
