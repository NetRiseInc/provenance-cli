use crate::sbom::types::SbomComponent;
use serde::Deserialize;

// ── SPDX JSON ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SpdxJson {
    #[serde(default)]
    packages: Vec<SpdxPackage>,
}

#[derive(Debug, Deserialize)]
struct SpdxPackage {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "versionInfo")]
    version_info: Option<String>,
    #[serde(default, rename = "externalRefs")]
    external_refs: Vec<SpdxExternalRef>,
}

#[derive(Debug, Deserialize)]
struct SpdxExternalRef {
    #[serde(default, rename = "referenceType")]
    reference_type: Option<String>,
    #[serde(default, rename = "referenceLocator")]
    reference_locator: Option<String>,
}

pub fn parse_spdx_json(content: &str) -> Result<Vec<SbomComponent>, String> {
    let doc: SpdxJson =
        serde_json::from_str(content).map_err(|e| format!("SPDX JSON parse error: {}", e))?;

    Ok(doc
        .packages
        .into_iter()
        .filter_map(|pkg| {
            let purl = pkg
                .external_refs
                .iter()
                .find(|r| {
                    r.reference_type
                        .as_deref()
                        .map(|t| t == "purl" || t == "purl-type")
                        .unwrap_or(false)
                })
                .and_then(|r| r.reference_locator.clone());

            purl.map(|p| SbomComponent {
                purl: p,
                name: pkg.name,
                version: pkg.version_info,
            })
        })
        .collect())
}

// ── SPDX Tag-Value ──────────────────────────────────────────────────────────

pub fn parse_spdx_tag_value(content: &str) -> Result<Vec<SbomComponent>, String> {
    let mut components = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_purl: Option<String> = None;
    let mut in_package = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(value) = line.strip_prefix("PackageName:") {
            // Save previous package
            if in_package {
                if let Some(purl) = current_purl.take() {
                    components.push(SbomComponent {
                        purl,
                        name: current_name.take(),
                        version: current_version.take(),
                    });
                }
            }
            current_name = Some(value.trim().to_string());
            current_version = None;
            current_purl = None;
            in_package = true;
        } else if let Some(value) = line.strip_prefix("PackageVersion:") {
            current_version = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("ExternalRef:") {
            // ExternalRef: PACKAGE-MANAGER purl pkg:...
            let parts: Vec<&str> = value.trim().splitn(3, ' ').collect();
            if parts.len() >= 3 && parts[1] == "purl" {
                current_purl = Some(parts[2].trim().to_string());
            }
        }
    }

    // Don't forget the last package
    if in_package {
        if let Some(purl) = current_purl.take() {
            components.push(SbomComponent {
                purl,
                name: current_name.take(),
                version: current_version.take(),
            });
        }
    }

    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spdx_json() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "xz-utils",
                    "versionInfo": "5.0.0-2",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:deb/debian/xz-utils@5.0.0-2?arch=kfreebsd-amd64&distro=debian-6"
                        }
                    ]
                },
                {
                    "name": "curl",
                    "versionInfo": "7.68.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:deb/debian/curl@7.68.0"
                        }
                    ]
                }
            ]
        }"#;
        let result = parse_spdx_json(json).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].purl.contains("xz-utils"));
    }

    #[test]
    fn test_parse_spdx_tag_value() {
        let tv = r#"SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT

PackageName: xz-utils
PackageVersion: 5.0.0-2
ExternalRef: PACKAGE-MANAGER purl pkg:deb/debian/xz-utils@5.0.0-2?arch=kfreebsd-amd64&distro=debian-6

PackageName: curl
PackageVersion: 7.68.0
ExternalRef: PACKAGE-MANAGER purl pkg:deb/debian/curl@7.68.0
"#;
        let result = parse_spdx_tag_value(tv).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].purl.contains("xz-utils"));
        assert!(result[1].purl.contains("curl"));
    }
}
