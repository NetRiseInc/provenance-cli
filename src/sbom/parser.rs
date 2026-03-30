use crate::sbom::csv as csv_parser;
use crate::sbom::cyclonedx;
use crate::sbom::spdx;
use crate::sbom::types::{SbomComponent, SbomFormat};
use std::collections::HashSet;

/// Normalize a PURL's distro qualifier for API compatibility.
///
/// Syft generates PURLs with full alpine distro versions (e.g., `distro=alpine-3.19.9`)
/// but the API indexes using major.minor only (`distro=alpine-3.19`).
/// This function strips the patch version from alpine distro qualifiers.
///
/// Rules:
/// - Only applies to PURLs with distro qualifier starting with `alpine-`
/// - Strips patch version: `alpine-3.19.9` -> `alpine-3.19`
/// - Does not touch non-alpine distros or PURLs without qualifiers
pub fn normalize_purl(purl: &str) -> String {
    // Quick check: if there's no '?' there are no qualifiers
    let Some(qmark_pos) = purl.find('?') else {
        return purl.to_string();
    };

    let base = &purl[..qmark_pos];
    let query_str = &purl[qmark_pos + 1..];

    // Parse qualifiers, normalize distro if alpine, rebuild
    let mut modified = false;
    let mut new_pairs: Vec<String> = Vec::new();

    for pair in query_str.split('&') {
        if let Some(value) = pair.strip_prefix("distro=") {
            // Decode the value in case it's URL-encoded
            let decoded = urlencoding::decode(value).unwrap_or_else(|_| value.into());
            if let Some(rest) = decoded.strip_prefix("alpine-") {
                // Check if it has 3 parts: major.minor.patch
                let parts: Vec<&str> = rest.splitn(3, '.').collect();
                if parts.len() == 3 {
                    // Strip patch: keep only major.minor
                    let normalized = format!("alpine-{}.{}", parts[0], parts[1]);
                    new_pairs.push(format!("distro={}", normalized));
                    modified = true;
                    continue;
                }
            }
            // Not alpine or not 3-part version: keep as-is
            new_pairs.push(pair.to_string());
        } else {
            new_pairs.push(pair.to_string());
        }
    }

    if modified {
        format!("{}?{}", base, new_pairs.join("&"))
    } else {
        purl.to_string()
    }
}

/// Detect SBOM format from content.
pub fn detect_format(content: &str, filename: Option<&str>) -> SbomFormat {
    let trimmed = content.trim();

    // Check filename extension first for ambiguous cases
    if let Some(name) = filename {
        let lower = name.to_lowercase();
        if lower.ends_with(".tv") || lower.ends_with(".spdx") {
            return SbomFormat::SpdxTagValue;
        }
        if lower.ends_with(".csv") {
            return SbomFormat::Csv;
        }
    }

    // JSON detection
    if trimmed.starts_with('{') {
        // Check if it's CycloneDX or SPDX
        if trimmed.contains("\"bomFormat\"") || trimmed.contains("\"components\"") {
            return SbomFormat::CycloneDxJson;
        }
        if trimmed.contains("\"spdxVersion\"") || trimmed.contains("\"SPDX-") {
            return SbomFormat::SpdxJson;
        }
        // Fallback: try to detect by field names
        if trimmed.contains("\"packages\"") && trimmed.contains("\"externalRefs\"") {
            return SbomFormat::SpdxJson;
        }
        // Default JSON to CycloneDX
        return SbomFormat::CycloneDxJson;
    }

    // XML detection
    if trimmed.starts_with("<?xml") || trimmed.starts_with("<bom") {
        return SbomFormat::CycloneDxXml;
    }

    // Tag-value detection
    if trimmed.contains("SPDXVersion:") || trimmed.contains("PackageName:") {
        return SbomFormat::SpdxTagValue;
    }

    // CSV detection: check for header line
    let first_line = trimmed.lines().next().unwrap_or("");
    let lower_first = first_line.to_lowercase();
    if lower_first.contains("purl")
        || lower_first.contains("package-url")
        || lower_first.contains("package_url")
    {
        return SbomFormat::Csv;
    }

    // CSV detection: check for component columns (type,namespace,name,version)
    {
        let cols: Vec<&str> = lower_first.split(',').map(|s| s.trim()).collect();
        if cols.contains(&"type") && cols.contains(&"name") {
            return SbomFormat::Csv;
        }
    }

    SbomFormat::Unknown
}

/// Parse SBOM content and return deduplicated components.
/// Returns (valid_components, warnings).
pub fn parse_sbom(
    content: &str,
    filename: Option<&str>,
) -> Result<(Vec<SbomComponent>, Vec<String>), String> {
    if content.trim().is_empty() {
        return Ok((vec![], vec!["SBOM file is empty".to_string()]));
    }

    let format = detect_format(content, filename);
    let components = match format {
        SbomFormat::CycloneDxJson => cyclonedx::parse_cyclonedx_json(content)?,
        SbomFormat::CycloneDxXml => cyclonedx::parse_cyclonedx_xml(content)?,
        SbomFormat::SpdxJson => spdx::parse_spdx_json(content)?,
        SbomFormat::SpdxTagValue => spdx::parse_spdx_tag_value(content)?,
        SbomFormat::Csv => csv_parser::parse_csv(content)?,
        SbomFormat::Unknown => {
            // Try each parser in order
            if let Ok(c) = cyclonedx::parse_cyclonedx_json(content) {
                if !c.is_empty() {
                    return Ok((c, vec![]));
                }
            }
            if let Ok(c) = spdx::parse_spdx_json(content) {
                if !c.is_empty() {
                    return Ok((c, vec![]));
                }
            }
            return Ok((
                vec![],
                vec!["Could not detect SBOM format; no packages found".to_string()],
            ));
        }
    };

    // Deduplicate by PURL
    let mut seen = HashSet::new();
    let mut warnings = Vec::new();
    let mut deduped = Vec::new();

    for mut comp in components {
        // Validate PURL
        if !comp.purl.starts_with("pkg:") {
            warnings.push(format!("Invalid PURL (skipped): {}", comp.purl));
            continue;
        }

        // Normalize distro qualifiers (e.g., alpine-3.19.9 -> alpine-3.19)
        comp.purl = normalize_purl(&comp.purl);

        if seen.insert(comp.purl.clone()) {
            deduped.push(comp);
        }
    }

    Ok((deduped, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cyclonedx_json() {
        let content = r#"{"bomFormat": "CycloneDX", "components": []}"#;
        assert_eq!(detect_format(content, None), SbomFormat::CycloneDxJson);
    }

    #[test]
    fn test_detect_spdx_json() {
        let content = r#"{"spdxVersion": "SPDX-2.3", "packages": []}"#;
        assert_eq!(detect_format(content, None), SbomFormat::SpdxJson);
    }

    #[test]
    fn test_detect_cyclonedx_xml() {
        let content =
            r#"<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.4"></bom>"#;
        assert_eq!(detect_format(content, None), SbomFormat::CycloneDxXml);
    }

    #[test]
    fn test_detect_spdx_tv() {
        let content = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0";
        assert_eq!(detect_format(content, None), SbomFormat::SpdxTagValue);
    }

    #[test]
    fn test_detect_csv() {
        let content = "purl,name\npkg:deb/debian/curl@7.0,curl";
        assert_eq!(detect_format(content, None), SbomFormat::Csv);
    }

    #[test]
    fn test_detect_by_extension() {
        let content = "some data";
        assert_eq!(
            detect_format(content, Some("test.tv")),
            SbomFormat::SpdxTagValue
        );
        assert_eq!(detect_format(content, Some("test.csv")), SbomFormat::Csv);
    }

    #[test]
    fn test_parse_empty() {
        let (components, warnings) = parse_sbom("", None).unwrap();
        assert!(components.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_parse_deduplicates() {
        let csv = "purl\npkg:deb/debian/curl@7.0\npkg:deb/debian/curl@7.0\n";
        let (components, _) = parse_sbom(csv, Some("test.csv")).unwrap();
        assert_eq!(components.len(), 1);
    }

    #[test]
    fn test_detect_csv_component_columns() {
        let content = "type,namespace,name,version\ndeb,debian,curl,7.68.0";
        assert_eq!(detect_format(content, None), SbomFormat::Csv);
    }

    #[test]
    fn test_parse_csv_component_columns() {
        let csv = "type,namespace,name,version\ndeb,debian,curl,7.68.0\nnpm,,lodash,4.17.21\n";
        let (components, _) = parse_sbom(csv, Some("test.csv")).unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].purl, "pkg:deb/debian/curl@7.68.0");
        assert_eq!(components[1].purl, "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn test_parse_filters_invalid_purls() {
        let csv = "purl\npkg:deb/debian/curl@7.0\nnot-a-purl\n";
        let (components, warnings) = parse_sbom(csv, Some("test.csv")).unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Invalid PURL"));
    }

    #[test]
    fn test_normalize_purl_alpine_strips_patch() {
        let input = "pkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64&distro=alpine-3.19.9";
        let expected = "pkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64&distro=alpine-3.19";
        assert_eq!(normalize_purl(input), expected);
    }

    #[test]
    fn test_normalize_purl_alpine_already_normalized() {
        let input = "pkg:apk/alpine/musl@1.2.4-r5?arch=x86_64&distro=alpine-3.19";
        assert_eq!(normalize_purl(input), input);
    }

    #[test]
    fn test_normalize_purl_debian_untouched() {
        let input = "pkg:deb/debian/curl@7.88.1-10+deb12u8?arch=amd64&distro=debian-12";
        assert_eq!(normalize_purl(input), input);
    }

    #[test]
    fn test_normalize_purl_no_qualifiers() {
        let input = "pkg:apk/alpine/musl@1.2.4";
        assert_eq!(normalize_purl(input), input);
    }

    #[test]
    fn test_normalize_purl_preserves_other_qualifiers() {
        let input =
            "pkg:apk/alpine/libcrypto3@3.1.7-r0?arch=x86_64&distro=alpine-3.19.4&upstream=openssl";
        let expected =
            "pkg:apk/alpine/libcrypto3@3.1.7-r0?arch=x86_64&distro=alpine-3.19&upstream=openssl";
        assert_eq!(normalize_purl(input), expected);
    }

    #[test]
    fn test_normalize_purl_alpine_single_part() {
        let input = "pkg:apk/alpine/busybox@1.36.1?distro=alpine-3";
        assert_eq!(normalize_purl(input), input);
    }

    #[test]
    fn test_normalize_purl_alpine_two_part() {
        let input = "pkg:apk/alpine/busybox@1.36.1?distro=alpine-3.19";
        assert_eq!(normalize_purl(input), input);
    }

    #[test]
    fn test_normalize_purl_distro_only_qualifier() {
        let input = "pkg:apk/alpine/zlib@1.3.1-r0?distro=alpine-3.19.7";
        let expected = "pkg:apk/alpine/zlib@1.3.1-r0?distro=alpine-3.19";
        assert_eq!(normalize_purl(input), expected);
    }

    #[test]
    fn test_parse_sbom_normalizes_alpine_purls() {
        let csv = "purl\npkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64&distro=alpine-3.19.9\n";
        let (components, _) = parse_sbom(csv, Some("test.csv")).unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(
            components[0].purl,
            "pkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64&distro=alpine-3.19"
        );
    }
}
