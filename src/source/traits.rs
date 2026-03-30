/// Represents the type of package source
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Sbom,
    Oci,
    SinglePackage,
    System,
}

/// Metadata about a package source
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SourceMetadata {
    pub name: String,
    pub source_type: SourceType,
    pub description: String,
}

/// A reference to a single package
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PackageRef {
    pub purl: String,
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Trait for anything that yields a list of packages to analyze.
/// Designed for extensibility — future system scan capability.
#[allow(dead_code, async_fn_in_trait)]
pub trait PackageSource {
    /// Human-readable name of this source
    fn name(&self) -> &str;

    /// Type of source
    fn source_type(&self) -> SourceType;

    /// Enumerate all packages from this source
    async fn enumerate_packages(&self) -> Result<Vec<PackageRef>, String>;

    /// Get metadata about this source
    fn metadata(&self) -> SourceMetadata;
}
