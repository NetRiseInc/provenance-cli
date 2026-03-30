use crate::api::ApiClient;
use crate::config::OutputFormat;
use anyhow::{bail, Result};
use std::process::Command;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &ApiClient,
    image_ref: &str,
    skip_verify: bool,
    format: OutputFormat,
    no_color: bool,
    ascii: bool,
    verbose: u8,
    api_url: &str,
    timeout: Option<u64>,
    quiet: bool,
) -> Result<()> {
    // Check for cosign and syft availability
    let has_cosign = Command::new("cosign").arg("version").output().is_ok();
    let has_syft = Command::new("syft").arg("version").output().is_ok();

    if !has_cosign && !has_syft {
        bail!(
            "Neither cosign nor syft is installed. At least one is required for OCI scanning.\n\n\
             Install cosign:\n\
             \tcurl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign\n\
             \tbrew install cosign  (macOS)\n\n\
             Install syft:\n\
             \tcurl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin\n\
             \tbrew install syft  (macOS)"
        );
    }

    let mut sbom_content = None;
    let mut sbom_source = "none";

    // Try cosign first
    if has_cosign {
        if verbose > 0 {
            eprintln!("[INFO] Attempting cosign SBOM extraction for {}", image_ref);
        }

        let mut cmd = Command::new("cosign");
        cmd.arg("download").arg("sbom").arg(image_ref);

        if skip_verify {
            // Add flag to skip verification if supported
        }

        match cmd.output() {
            Ok(output) if output.status.success() => {
                let content = String::from_utf8_lossy(&output.stdout).to_string();
                if !content.trim().is_empty() {
                    sbom_content = Some(content);
                    sbom_source = "cosign";
                }
            }
            Ok(output) => {
                if verbose > 0 {
                    eprintln!(
                        "[INFO] cosign SBOM download failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
            Err(e) => {
                if verbose > 0 {
                    eprintln!("[INFO] cosign execution failed: {}", e);
                }
            }
        }
    }

    // Fall back to syft
    if sbom_content.is_none() && has_syft {
        if verbose > 0 {
            eprintln!("[INFO] Attempting syft SBOM generation for {}", image_ref);
        }

        let output = Command::new("syft")
            .arg(image_ref)
            .arg("-o")
            .arg("cyclonedx-json")
            .output()?;

        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout).to_string();
            if !content.trim().is_empty() {
                sbom_content = Some(content);
                sbom_source = "syft";
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("syft failed to generate SBOM: {}", stderr);
        }
    }

    let content = match sbom_content {
        Some(c) => c,
        None => bail!("No SBOM could be extracted from image {}", image_ref),
    };

    if verbose > 0 {
        eprintln!(
            "[INFO] SBOM extracted via {} ({} bytes)",
            sbom_source,
            content.len()
        );
    }

    // Cache the extracted SBOM
    let cache_dir = std::env::temp_dir().join("provenance-oci-cache");
    std::fs::create_dir_all(&cache_dir).ok();
    let cache_file = cache_dir.join(format!("{}.json", image_ref.replace(['/', ':', '@'], "_")));
    std::fs::write(&cache_file, &content).ok();

    // Process through standard SBOM scanner using the cached file
    let temp_path = cache_file.to_string_lossy().to_string();
    super::sbom::run(
        client,
        Some(&temp_path),
        false,
        false,
        format,
        no_color,
        ascii,
        verbose,
        api_url,
        timeout,
        &[],
        None,
        quiet,
    )
    .await
    .map(|_exit_code| ())
}
