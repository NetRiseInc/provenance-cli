#[allow(dead_code)]
pub mod oci_source;
#[allow(dead_code)]
pub mod sbom_source;
pub mod traits;

#[allow(unused_imports)]
pub use oci_source::OciSource;
#[allow(unused_imports)]
pub use sbom_source::SbomSource;
#[allow(unused_imports)]
pub use traits::{PackageRef, PackageSource, SourceMetadata, SourceType};

/// SinglePackageSource wraps a single PURL for uniform processing
#[allow(dead_code)]
pub struct SinglePackageSource {
    purl: String,
}

#[allow(dead_code)]
impl SinglePackageSource {
    pub fn new(purl: String) -> Self {
        Self { purl }
    }
}

impl PackageSource for SinglePackageSource {
    fn name(&self) -> &str {
        &self.purl
    }

    fn source_type(&self) -> SourceType {
        SourceType::SinglePackage
    }

    async fn enumerate_packages(&self) -> Result<Vec<PackageRef>, String> {
        Ok(vec![PackageRef {
            purl: self.purl.clone(),
            name: None,
            version: None,
        }])
    }

    fn metadata(&self) -> SourceMetadata {
        SourceMetadata {
            name: self.purl.clone(),
            source_type: SourceType::SinglePackage,
            description: format!("Single package: {}", self.purl),
        }
    }
}

/// SystemSource — stub for future system package scanning.
/// Intended to integrate with dpkg, rpm, apk, etc. to enumerate
/// packages installed on the local system.
///
/// # Future Implementation
///
/// When implemented, this would:
/// - Detect the package manager (dpkg on Debian/Ubuntu, rpm on RHEL/Fedora, apk on Alpine)
/// - Run the appropriate command to list installed packages
/// - Convert each installed package to a PURL
/// - Return the list of PURLs for analysis
///
/// # Example (future)
/// ```ignore
/// let source = SystemSource::detect()?;
/// let packages = source.enumerate_packages().await?;
/// ```
#[allow(dead_code)]
pub struct SystemSource;

impl PackageSource for SystemSource {
    fn name(&self) -> &str {
        "system"
    }

    fn source_type(&self) -> SourceType {
        SourceType::System
    }

    async fn enumerate_packages(&self) -> Result<Vec<PackageRef>, String> {
        unimplemented!(
            "System package scanning is not yet implemented. \
             Future versions will support dpkg, rpm, and apk package managers."
        )
    }

    fn metadata(&self) -> SourceMetadata {
        SourceMetadata {
            name: "system".to_string(),
            source_type: SourceType::System,
            description: "Local system packages (not yet implemented)".to_string(),
        }
    }
}
