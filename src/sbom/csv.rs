use crate::sbom::types::SbomComponent;

pub fn parse_csv(content: &str) -> Result<Vec<SbomComponent>, String> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(content.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| format!("CSV header parse error: {}", e))?
        .clone();

    // Find the PURL column index (optional — we can construct PURLs from component columns)
    let purl_idx = headers.iter().position(|h| {
        let lower = h.to_lowercase().trim().to_string();
        lower == "purl" || lower == "package-url" || lower == "package_url" || lower == "packageurl"
    });

    // Find component columns for PURL construction
    let type_idx = headers
        .iter()
        .position(|h| h.to_lowercase().trim() == "type");
    let namespace_idx = headers
        .iter()
        .position(|h| h.to_lowercase().trim() == "namespace");
    let name_idx = headers
        .iter()
        .position(|h| h.to_lowercase().trim() == "name" || h.to_lowercase().trim() == "package");
    let version_idx = headers
        .iter()
        .position(|h| h.to_lowercase().trim() == "version");

    // We need either a PURL column, or at minimum type + name columns
    let can_construct_purl = type_idx.is_some() && name_idx.is_some();
    if purl_idx.is_none() && !can_construct_purl {
        return Err(
            "CSV does not contain a recognized PURL column (expected: purl, package-url, package_url, or packageurl) \
             and does not have type+name columns to construct PURLs".to_string()
        );
    }

    let mut components = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| format!("CSV record parse error: {}", e))?;

        // Try to get PURL directly first
        let purl = if let Some(idx) = purl_idx {
            record.get(idx).map(|s| s.trim().to_string())
        } else {
            None
        };

        let purl = match purl {
            Some(p) if !p.is_empty() => p,
            _ if can_construct_purl => {
                // Construct PURL from type, namespace, name, version columns
                let pkg_type = type_idx
                    .and_then(|i| record.get(i))
                    .map(|s| s.trim())
                    .unwrap_or("");
                let namespace = namespace_idx
                    .and_then(|i| record.get(i))
                    .map(|s| s.trim())
                    .unwrap_or("");
                let name = name_idx
                    .and_then(|i| record.get(i))
                    .map(|s| s.trim())
                    .unwrap_or("");
                let version = version_idx
                    .and_then(|i| record.get(i))
                    .map(|s| s.trim())
                    .unwrap_or("");

                if pkg_type.is_empty() || name.is_empty() {
                    continue;
                }

                let mut purl_str = if namespace.is_empty() {
                    format!("pkg:{}/{}", pkg_type, name)
                } else {
                    format!("pkg:{}/{}/{}", pkg_type, namespace, name)
                };

                if !version.is_empty() {
                    purl_str.push('@');
                    purl_str.push_str(version);
                }

                purl_str
            }
            _ => continue,
        };

        let comp_name = name_idx
            .and_then(|i| record.get(i))
            .map(|s| s.trim().to_string());
        let comp_version = version_idx
            .and_then(|i| record.get(i))
            .map(|s| s.trim().to_string());

        components.push(SbomComponent {
            purl,
            name: comp_name,
            version: comp_version,
        });
    }

    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv() {
        let csv_data = "purl,name,version\npkg:deb/debian/xz-utils@5.0.0-2?arch=kfreebsd-amd64&distro=debian-6,xz-utils,5.0.0-2\npkg:deb/debian/curl@7.68.0,curl,7.68.0\n";
        let result = parse_csv(csv_data).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].purl.contains("xz-utils"));
    }

    #[test]
    fn test_parse_csv_package_url_header() {
        let csv_data = "package-url\npkg:deb/debian/curl@7.68.0\n";
        let result = parse_csv(csv_data).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_csv_no_purl_column() {
        let csv_data = "name,version\ncurl,7.68.0\n";
        let result = parse_csv(csv_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_csv_component_columns() {
        let csv_data = "type,namespace,name,version\ndeb,debian,curl,7.68.0\nnpm,,lodash,4.17.21\n";
        let result = parse_csv(csv_data).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].purl, "pkg:deb/debian/curl@7.68.0");
        assert_eq!(result[1].purl, "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn test_parse_csv_component_columns_no_version() {
        let csv_data = "type,namespace,name\ndeb,debian,curl\n";
        let result = parse_csv(csv_data).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:deb/debian/curl");
    }

    #[test]
    fn test_parse_csv_component_columns_no_namespace() {
        let csv_data = "type,name,version\nnpm,lodash,4.17.21\n";
        let result = parse_csv(csv_data).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn test_parse_csv_component_columns_skip_empty_type() {
        let csv_data = "type,name,version\n,lodash,4.17.21\nnpm,express,4.18.0\n";
        let result = parse_csv(csv_data).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:npm/express@4.18.0");
    }
}
