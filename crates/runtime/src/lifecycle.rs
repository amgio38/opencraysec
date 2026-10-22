//! Release and end-of-life data for runtime products, and the parsers for the two feeds it comes
//! from: endoflife.date (every product, one file) and php.net (the freshest PHP patch releases).
//!
//! Nothing here touches the network; `opencraysec-db` downloads and stores the feeds.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One release line of a product (PHP `8.2`, Node.js `22`, nginx `1.28`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    /// The release line, as the product names it.
    pub name: String,
    /// First day the line is end of life (`YYYY-MM-DD`), when the feed gives one.
    #[serde(default)]
    pub eol_from: Option<String>,
    /// True when the feed already counted the line as end of life when it was downloaded.
    #[serde(default)]
    pub is_eol: bool,
    /// Latest patch release of the line.
    #[serde(default)]
    pub latest: Option<String>,
}

/// A product and its release lines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Product {
    /// The product's slug in the feed (`php`, `nodejs`).
    pub name: String,
    /// Other names the feed knows it by.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Release lines, newest first.
    pub releases: Vec<Release>,
}

/// The stored end-of-life dataset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lifecycle {
    /// RFC 3339 UTC time the dataset was downloaded.
    pub updated_at: String,
    /// All products in the feed.
    pub products: Vec<Product>,
}

impl Lifecycle {
    /// Finds a product by slug or alias, ignoring case.
    pub fn find(&self, name: &str) -> Option<&Product> {
        let wanted = name.trim().to_ascii_lowercase();
        self.products.iter().find(|p| {
            p.name.eq_ignore_ascii_case(&wanted)
                || p.aliases.iter().any(|a| a.eq_ignore_ascii_case(&wanted))
        })
    }
}

/// The newest patch release per release line, from a vendor's own release feed. Vendors publish
/// before aggregators do, so this wins when it is ahead.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorLatest {
    /// The product's slug (`php`).
    pub product: String,
    /// RFC 3339 UTC time the feed was downloaded.
    pub updated_at: String,
    /// Release line to its newest patch release (`"8.4"` to `"8.4.27"`).
    pub latest: BTreeMap<String, String>,
}

/// Reduces the endoflife.date API v1 `products/full` document to what a scan needs.
pub fn parse_endoflife(json: &[u8], updated_at: String) -> Result<Lifecycle, String> {
    let doc: Value =
        serde_json::from_slice(json).map_err(|e| format!("bad endoflife.date: {e}"))?;
    let list = doc
        .get("result")
        .and_then(Value::as_array)
        .ok_or("endoflife.date feed has no `result` array")?;
    let products: Vec<Product> = list
        .iter()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?.to_string();
            let aliases = p
                .get("aliases")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let releases = p
                .get("releases")?
                .as_array()?
                .iter()
                .filter_map(|r| {
                    Some(Release {
                        name: r.get("name")?.as_str()?.to_string(),
                        eol_from: r.get("eolFrom").and_then(Value::as_str).map(str::to_string),
                        is_eol: r.get("isEol").and_then(Value::as_bool).unwrap_or(false),
                        latest: r
                            .get("latest")
                            .and_then(|l| l.get("name"))
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    })
                })
                .collect();
            Some(Product {
                name,
                aliases,
                releases,
            })
        })
        .collect();
    if products.is_empty() {
        return Err("endoflife.date feed contained no products".into());
    }
    Ok(Lifecycle {
        updated_at,
        products,
    })
}

/// Reads php.net's `releases/active.php`: `{ "8": { "8.4": { "version": "8.4.27", .. }, .. } }`.
pub fn parse_php_active(json: &[u8], updated_at: String) -> Result<VendorLatest, String> {
    let doc: Value = serde_json::from_slice(json).map_err(|e| format!("bad php.net feed: {e}"))?;
    let majors = doc.as_object().ok_or("php.net feed is not an object")?;
    let mut latest = BTreeMap::new();
    for lines in majors.values().filter_map(Value::as_object) {
        for (line, info) in lines {
            if let Some(v) = info.get("version").and_then(Value::as_str) {
                latest.insert(line.clone(), v.to_string());
            }
        }
    }
    if latest.is_empty() {
        return Err("php.net feed listed no releases".into());
    }
    Ok(VendorLatest {
        product: "php".into(),
        updated_at,
        latest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EOL: &str = r#"{"result":[
        {"name":"php","aliases":["php-fpm"],"releases":[
            {"name":"8.4","eolFrom":"2028-12-31","isEol":false,"latest":{"name":"8.4.26"}},
            {"name":"7.4","eolFrom":"2022-11-28","isEol":true,"latest":{"name":"7.4.33"}}]},
        {"name":"nodejs","releases":[{"name":"22","eolFrom":null,"isEol":false,"latest":null}]},
        {"releases":[]}]}"#;

    #[test]
    fn endoflife_is_reduced_and_tolerates_gaps() {
        let l = parse_endoflife(EOL.as_bytes(), "t".into()).expect("parses");
        assert_eq!(l.products.len(), 2, "a product without a name is dropped");
        let php = l.find("PHP-FPM").expect("alias, any case");
        assert_eq!(php.name, "php");
        assert_eq!(php.releases[1].name, "7.4");
        assert!(php.releases[1].is_eol);
        assert_eq!(php.releases[0].latest.as_deref(), Some("8.4.26"));
        assert_eq!(l.find("nodejs").expect("slug").releases[0].eol_from, None);
        assert!(l.find("nope").is_none());
    }

    #[test]
    fn endoflife_rejects_an_unusable_document() {
        assert!(parse_endoflife(b"{}", "t".into()).is_err());
        assert!(parse_endoflife(b"not json", "t".into()).is_err());
        assert!(parse_endoflife(br#"{"result":[]}"#, "t".into()).is_err());
    }

    #[test]
    fn php_active_feed_maps_line_to_newest_patch() {
        let json = br#"{"8":{"8.4":{"version":"8.4.27","date":"x"},"8.2":{"version":"8.2.35"}},
                        "7":{"7.4":{"announcement":true}}}"#;
        let v = parse_php_active(json, "t".into()).expect("parses");
        assert_eq!(v.latest.get("8.4").map(String::as_str), Some("8.4.27"));
        assert_eq!(v.latest.get("8.2").map(String::as_str), Some("8.2.35"));
        assert!(
            !v.latest.contains_key("7.4"),
            "no `version`, nothing to say"
        );
        assert!(parse_php_active(b"[]", "t".into()).is_err());
        assert!(parse_php_active(b"{}", "t".into()).is_err());
    }
}
