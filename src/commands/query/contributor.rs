use crate::api::ApiClient;
use crate::config::OutputFormat;
use crate::output::{HumanFormatter, SarifOutput};
use anyhow::Result;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &ApiClient,
    identifier: &str,
    security: bool,
    format: OutputFormat,
    no_color: bool,
    ascii: bool,
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    let resp = client.get_contributor(identifier).await?;

    match format {
        OutputFormat::Json => {
            let mut json_val = serde_json::to_value(&resp)?;
            if security && identifier.contains('@') {
                match client.get_contributor_security(identifier).await {
                    Ok(sec_resp) => {
                        json_val["security"] = serde_json::to_value(&sec_resp.data)?;
                    }
                    Err(e) => {
                        eprintln!("[WARN] Failed to fetch security data: {}", e);
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&json_val)?);
        }
        OutputFormat::Sarif => {
            let mut sarif = SarifOutput::from_contributor(&resp);
            // If security is requested, merge security findings
            if security && identifier.contains('@') {
                match client.get_contributor_security(identifier).await {
                    Ok(sec_resp) => {
                        let sec_sarif = SarifOutput::from_contributor_security(&sec_resp);
                        // Merge rules and results from security SARIF into the main one
                        if let (Some(main_run), Some(sec_run)) =
                            (sarif.runs.first_mut(), sec_sarif.runs.first())
                        {
                            main_run
                                .tool
                                .driver
                                .rules
                                .extend(sec_run.tool.driver.rules.iter().cloned());
                            main_run.results.extend(sec_run.results.iter().cloned());
                        }
                    }
                    Err(e) => {
                        eprintln!("[WARN] Failed to fetch security data: {}", e);
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        OutputFormat::Human => {
            if quiet {
                let repo_count = resp
                    .data
                    .summary
                    .as_ref()
                    .map(|s| s.repos.len())
                    .unwrap_or(0);
                let purl_count = resp
                    .data
                    .summary
                    .as_ref()
                    .map(|s| s.purls.len())
                    .unwrap_or(0);
                println!(
                    "{}: {} repos, {} packages",
                    identifier, repo_count, purl_count
                );
            } else {
                let fmt = HumanFormatter::new(no_color, ascii, verbose);
                print!("{}", fmt.format_contributor(&resp));

                if security {
                    if identifier.contains('@') {
                        match client.get_contributor_security(identifier).await {
                            Ok(sec_resp) => {
                                print!("{}", fmt.format_contributor_security(&sec_resp));
                            }
                            Err(e) => {
                                eprintln!("[WARN] Failed to fetch security data: {}", e);
                            }
                        }
                    } else {
                        eprintln!(
                            "[WARN] --security requires an email address (contains '@'). Got: {}",
                            identifier
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
