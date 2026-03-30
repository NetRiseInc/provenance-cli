use crate::api::ApiClient;
use crate::config::OutputFormat;
use crate::output::{HumanFormatter, SarifOutput};
use anyhow::{bail, Result};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &ApiClient,
    purl: &str,
    health: bool,
    search: bool,
    dependents: bool,
    format: OutputFormat,
    no_color: bool,
    ascii: bool,
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    // Validate PURL
    if !purl.starts_with("pkg:") {
        bail!(
            "Invalid PURL format: '{}'. A valid PURL starts with 'pkg:' (e.g., pkg:deb/debian/curl@7.0.0). \
             See https://github.com/package-url/purl-spec for the specification.",
            purl
        );
    }

    if search {
        let resp = client.search_package(purl).await?;
        match format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            OutputFormat::Sarif => {
                let sarif = SarifOutput::from_package_search(&resp, purl);
                println!("{}", serde_json::to_string_pretty(&sarif)?);
            }
            OutputFormat::Human => {
                if quiet {
                    println!("{} results", resp.purls.len());
                } else {
                    let fmt = HumanFormatter::new(no_color, ascii, verbose);
                    print!("{}", fmt.format_package_search(&resp));
                }
            }
        }
        return Ok(());
    }

    if dependents {
        let resp = client.get_package_dependents(purl).await?;
        match format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            OutputFormat::Sarif => {
                let sarif = SarifOutput::from_package_dependents(&resp, purl);
                println!("{}", serde_json::to_string_pretty(&sarif)?);
            }
            OutputFormat::Human => {
                if quiet {
                    println!("{} dependents", resp.purls.len());
                } else {
                    let fmt = HumanFormatter::new(no_color, ascii, verbose);
                    print!("{}", fmt.format_package_dependents(&resp));
                }
            }
        }
        return Ok(());
    }

    let resp = client.get_package(purl).await?;

    match format {
        OutputFormat::Json => {
            let mut json_val = serde_json::to_value(&resp.data)?;
            if health {
                if let Some(ref repo_details) = resp.data.repository_details {
                    if let Some(ref repo_url) = repo_details.url {
                        match client.get_repo_health(repo_url).await {
                            Ok(health_resp) => {
                                json_val["health"] = serde_json::to_value(&health_resp.data)?;
                            }
                            Err(e) => {
                                eprintln!("[WARN] Failed to fetch health data: {}", e);
                            }
                        }
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&json_val)?);
        }
        OutputFormat::Sarif => {
            let sarif = SarifOutput::from_package(&resp);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        OutputFormat::Human => {
            if quiet {
                println!("{}: {} advisories", purl, resp.data.advisories.len());
            } else {
                let fmt = HumanFormatter::new(no_color, ascii, verbose);
                print!("{}", fmt.format_package(&resp));

                if health {
                    if let Some(ref repo_details) = resp.data.repository_details {
                        if let Some(ref repo_url) = repo_details.url {
                            match client.get_repo_health(repo_url).await {
                                Ok(health_resp) => {
                                    print!("{}", fmt.format_health(&health_resp));
                                }
                                Err(e) => {
                                    eprintln!("[WARN] Failed to fetch health data: {}", e);
                                }
                            }
                        } else {
                            eprintln!("[WARN] No repository URL available for health check");
                        }
                    } else {
                        eprintln!("[WARN] No repository details available for health check");
                    }
                }
            }
        }
    }

    Ok(())
}
