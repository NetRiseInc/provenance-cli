use crate::api::ApiClient;
use crate::config::OutputFormat;
use crate::output::{HumanFormatter, SarifOutput};
use anyhow::Result;

pub async fn run(
    client: &ApiClient,
    advisory_id: &str,
    format: OutputFormat,
    no_color: bool,
    ascii: bool,
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    let resp = client.get_advisory(advisory_id).await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        OutputFormat::Sarif => {
            let sarif = SarifOutput::from_advisory(&resp);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        OutputFormat::Human => {
            if quiet {
                println!("{}", resp.name);
            } else {
                let fmt = HumanFormatter::new(no_color, ascii, verbose);
                print!("{}", fmt.format_advisory(&resp));
            }
        }
    }

    Ok(())
}
