use crate::sbom::types::SbomComponent;
use serde::Deserialize;

// ── CycloneDX JSON ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CycloneDxJson {
    #[serde(default)]
    components: Vec<CdxComponent>,
}

#[derive(Debug, Deserialize)]
struct CdxComponent {
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

pub fn parse_cyclonedx_json(content: &str) -> Result<Vec<SbomComponent>, String> {
    let doc: CycloneDxJson =
        serde_json::from_str(content).map_err(|e| format!("CycloneDX JSON parse error: {}", e))?;

    Ok(doc
        .components
        .into_iter()
        .filter_map(|c| {
            c.purl.map(|purl| SbomComponent {
                purl,
                name: c.name,
                version: c.version,
            })
        })
        .collect())
}

// ── CycloneDX XML ───────────────────────────────────────────────────────────

pub fn parse_cyclonedx_xml(content: &str) -> Result<Vec<SbomComponent>, String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(content);
    let mut components = Vec::new();
    let mut in_component = false;
    let mut in_purl = false;
    let mut in_name = false;
    let mut in_version = false;
    let mut current_purl = None;
    let mut current_name = None;
    let mut current_version = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match local.as_str() {
                    "component" => {
                        in_component = true;
                        current_purl = None;
                        current_name = None;
                        current_version = None;
                    }
                    "purl" if in_component => in_purl = true,
                    "name" if in_component => in_name = true,
                    "version" if in_component => in_version = true,
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_purl {
                    current_purl = Some(e.unescape().unwrap_or_default().trim().to_string());
                } else if in_name {
                    current_name = Some(e.unescape().unwrap_or_default().trim().to_string());
                } else if in_version {
                    current_version = Some(e.unescape().unwrap_or_default().trim().to_string());
                }
            }
            Ok(Event::End(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match local.as_str() {
                    "component" => {
                        if in_component {
                            if let Some(purl) = current_purl.take() {
                                components.push(SbomComponent {
                                    purl,
                                    name: current_name.take(),
                                    version: current_version.take(),
                                });
                            }
                        }
                        in_component = false;
                    }
                    "purl" => in_purl = false,
                    "name" => in_name = false,
                    "version" => in_version = false,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("CycloneDX XML parse error: {}", e)),
            _ => {}
        }
    }

    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cyclonedx_json() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"type": "library", "name": "xz-utils", "version": "5.0.0-2", "purl": "pkg:deb/debian/xz-utils@5.0.0-2?arch=kfreebsd-amd64&distro=debian-6"},
                {"type": "library", "name": "curl", "version": "7.68.0", "purl": "pkg:deb/debian/curl@7.68.0"},
                {"type": "library", "name": "no-purl", "version": "1.0.0"}
            ]
        }"#;
        let result = parse_cyclonedx_json(json).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].purl.contains("xz-utils"));
        assert!(result[1].purl.contains("curl"));
    }

    #[test]
    fn test_parse_cyclonedx_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4">
  <components>
    <component type="library">
      <name>xz-utils</name>
      <version>5.0.0-2</version>
      <purl>pkg:deb/debian/xz-utils@5.0.0-2?arch=kfreebsd-amd64&amp;distro=debian-6</purl>
    </component>
    <component type="library">
      <name>curl</name>
      <version>7.68.0</version>
      <purl>pkg:deb/debian/curl@7.68.0</purl>
    </component>
  </components>
</bom>"#;
        let result = parse_cyclonedx_xml(xml).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].purl.contains("xz-utils"));
    }

    #[test]
    fn test_parse_empty_cyclonedx_json() {
        let json = r#"{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}"#;
        let result = parse_cyclonedx_json(json).unwrap();
        assert_eq!(result.len(), 0);
    }
}
