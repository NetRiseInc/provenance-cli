use crate::source::traits::*;

pub struct OciSource {
    image_ref: String,
}

impl OciSource {
    pub fn new(image_ref: String) -> Self {
        Self { image_ref }
    }
}

impl PackageSource for OciSource {
    fn name(&self) -> &str {
        &self.image_ref
    }

    fn source_type(&self) -> SourceType {
        SourceType::Oci
    }

    async fn enumerate_packages(&self) -> Result<Vec<PackageRef>, String> {
        // OCI scanning delegates to cosign/syft externally.
        // The actual implementation is in commands/scan/oci.rs
        Err("OCI source package enumeration should go through the OCI scan command".to_string())
    }

    fn metadata(&self) -> SourceMetadata {
        SourceMetadata {
            name: self.image_ref.clone(),
            source_type: SourceType::Oci,
            description: format!("OCI image: {}", self.image_ref),
        }
    }
}
