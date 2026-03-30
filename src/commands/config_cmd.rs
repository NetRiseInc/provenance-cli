use crate::api::ApiClient;
use crate::config::{self, AppConfig};
use anyhow::Result;

pub fn show(cfg: &AppConfig) -> Result<()> {
    println!("Effective Configuration:");
    println!(
        "  Token:       {}",
        cfg.token
            .as_deref()
            .map(config::redact_token)
            .unwrap_or_else(|| "(not set)".to_string())
    );
    println!("  API URL:     {}", cfg.api_url);
    println!("  Format:      {}", cfg.format);
    println!("  Concurrency: {}", cfg.concurrency);
    println!("  Timeout:     {}s", cfg.timeout);
    println!("  Verbose:     {}", cfg.verbose);
    println!("  No Color:    {}", cfg.no_color);
    println!("  ASCII:       {}", cfg.ascii);

    if let Some(path) = config::config_file_path() {
        if path.exists() {
            println!("  Config File: {}", path.display());
        } else {
            println!("  Config File: {} (not found)", path.display());
        }
    }

    Ok(())
}

pub async fn test(cfg: &AppConfig) -> Result<()> {
    let token = cfg
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No API token configured. Set PROVENANCE_API_TOKEN environment variable or use --token flag."
            )
        })?;

    let client = ApiClient::new(
        &cfg.api_url,
        token,
        cfg.timeout,
        cfg.concurrency,
        cfg.verbose,
    )?;

    match client.test_connectivity().await {
        Ok(()) => {
            println!("API connection: OK");
            println!("  URL:   {}", cfg.api_url);
            println!("  Token: {}", config::redact_token(token));
            println!("  Status: Connected successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!("API connection: FAILED");
            eprintln!("  URL:   {}", cfg.api_url);
            eprintln!("  Error: {}", e);
            Err(anyhow::anyhow!("API connectivity test failed: {}", e))
        }
    }
}
