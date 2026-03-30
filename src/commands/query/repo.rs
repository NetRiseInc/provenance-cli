use crate::api::ApiClient;
use crate::config::OutputFormat;
use crate::output::{HumanFormatter, SarifOutput};
use anyhow::Result;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &ApiClient,
    repo_url: &str,
    health: bool,
    format: OutputFormat,
    no_color: bool,
    ascii: bool,
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    let resp = client.get_repo(repo_url).await?;

    match format {
        OutputFormat::Json => {
            let mut json_val = serde_json::to_value(&resp.data)?;
            if health {
                match client.get_repo_health(repo_url).await {
                    Ok(health_resp) => {
                        json_val["health"] = serde_json::to_value(&health_resp.data)?;
                    }
                    Err(e) => {
                        eprintln!("[WARN] Failed to fetch health data: {}", e);
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&json_val)?);
        }
        OutputFormat::Sarif => {
            let sarif = SarifOutput::from_repo(&resp);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        OutputFormat::Human => {
            if quiet {
                println!(
                    "{}: {} packages, {} advisories",
                    repo_url,
                    resp.data.packages.len(),
                    resp.data.advisories.len()
                );
            } else {
                let fmt = HumanFormatter::new(no_color, ascii, verbose);
                print!("{}", fmt.format_repo(&resp));

                if health {
                    match client.get_repo_health(repo_url).await {
                        Ok(health_resp) => {
                            print!("{}", fmt.format_health(&health_resp));
                        }
                        Err(e) => {
                            eprintln!("[WARN] Failed to fetch health data: {}", e);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
