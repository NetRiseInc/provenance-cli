use crate::sbom;
use crate::source::traits::*;

pub struct SbomSource {
    filename: String,
    content: String,
}

impl SbomSource {
    pub fn new(filename: String, content: String) -> Self {
        Self { filename, content }
    }
}

impl PackageSource for SbomSource {
    fn name(&self) -> &str {
        &self.filename
    }

    fn source_type(&self) -> SourceType {
        SourceType::Sbom
    }

    async fn enumerate_packages(&self) -> Result<Vec<PackageRef>, String> {
        let (components, _warnings) = sbom::parse_sbom(&self.content, Some(&self.filename))?;

        Ok(components
            .into_iter()
            .map(|c| PackageRef {
                purl: c.purl,
                name: c.name,
                version: c.version,
            })
            .collect())
    }

    fn metadata(&self) -> SourceMetadata {
        SourceMetadata {
            name: self.filename.clone(),
            source_type: SourceType::Sbom,
            description: format!("SBOM file: {}", self.filename),
        }
    }
}
