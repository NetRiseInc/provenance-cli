/// Normalized SBOM component representation
#[derive(Debug, Clone)]
pub struct SbomComponent {
    pub purl: String,
    #[allow(dead_code)]
    pub name: Option<String>,
    #[allow(dead_code)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDxJson,
    CycloneDxXml,
    SpdxJson,
    SpdxTagValue,
    Csv,
    Unknown,
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomFormat::CycloneDxJson => write!(f, "CycloneDX JSON"),
            SbomFormat::CycloneDxXml => write!(f, "CycloneDX XML"),
            SbomFormat::SpdxJson => write!(f, "SPDX JSON"),
            SbomFormat::SpdxTagValue => write!(f, "SPDX Tag-Value"),
            SbomFormat::Csv => write!(f, "CSV"),
            SbomFormat::Unknown => write!(f, "Unknown"),
        }
    }
}
