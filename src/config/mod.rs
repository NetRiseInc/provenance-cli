pub mod types;

pub use types::{AppConfig, ConfigFile, OutputFormat};

use std::path::PathBuf;

/// Load config file from ~/.config/provenance/config.yaml if it exists.
pub fn load_config_file() -> Option<ConfigFile> {
    let path = config_file_path()?;
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    serde_yaml::from_str(&content).ok()
}

pub fn config_file_path() -> Option<PathBuf> {
    dirs_path().map(|d| d.join("config.yaml"))
}

fn dirs_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".config").join("provenance"))
}

/// Build AppConfig from layered sources: CLI flags > env vars > config file > defaults
#[allow(clippy::too_many_arguments)]
pub fn build_config(
    cli_token: Option<&str>,
    cli_api_url: Option<&str>,
    cli_format: Option<&str>,
    cli_concurrency: Option<usize>,
    cli_timeout: Option<u64>,
    cli_verbose: u8,
    cli_quiet: bool,
    cli_no_color: bool,
    cli_ascii: bool,
) -> AppConfig {
    let file_config = load_config_file().unwrap_or_default();
    let defaults = AppConfig::default();

    // Token: CLI > env (PROVENANCE_API_TOKEN, fallback NETRISE_API_TOKEN) > config file
    let token = cli_token
        .map(|s| s.to_string())
        .or_else(|| {
            std::env::var("PROVENANCE_API_TOKEN")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            std::env::var("NETRISE_API_TOKEN")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or(file_config.token);

    // API URL: CLI > env (PROVENANCE_API_URL, fallback NETRISE_API_URL) > config file > default
    let api_url = cli_api_url
        .map(|s| s.to_string())
        .or_else(|| {
            std::env::var("PROVENANCE_API_URL")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            std::env::var("NETRISE_API_URL")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or(file_config.api_url)
        .unwrap_or(defaults.api_url);

    // Format: CLI > config file > default
    let format = cli_format
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            file_config
                .default_format
                .as_deref()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(defaults.format);

    let concurrency = cli_concurrency
        .or(file_config.concurrency)
        .unwrap_or(defaults.concurrency);

    let timeout = cli_timeout
        .or(file_config.timeout)
        .unwrap_or(defaults.timeout);

    // Detect NO_COLOR env var or piped stdout
    let is_tty = atty_check();
    let no_color_env = std::env::var("NO_COLOR").is_ok();
    let effective_no_color = cli_no_color || no_color_env || !is_tty;

    AppConfig {
        token,
        api_url,
        format,
        concurrency,
        timeout,
        verbose: cli_verbose,
        quiet: cli_quiet,
        no_color: effective_no_color,
        ascii: cli_ascii,
    }
}

fn atty_check() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

pub fn redact_token(token: &str) -> String {
    if token.len() <= 4 {
        return "****".to_string();
    }
    format!("****{}", &token[token.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_long_token() {
        let redacted = redact_token("test-token-for-unit-testing-only-not-real");
        assert!(redacted.starts_with("****"));
        assert!(redacted.ends_with("real"));
        assert!(!redacted.contains("test-token"));
    }

    #[test]
    fn test_redact_short_token() {
        assert_eq!(redact_token("abc"), "****");
        assert_eq!(redact_token(""), "****");
    }

    #[test]
    fn test_output_format_parsing() {
        assert_eq!(
            "human".parse::<OutputFormat>().unwrap(),
            OutputFormat::Human
        );
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(
            "sarif".parse::<OutputFormat>().unwrap(),
            OutputFormat::Sarif
        );
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Human.to_string(), "human");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Sarif.to_string(), "sarif");
    }

    #[test]
    fn test_build_config_defaults() {
        // Temporarily clear env vars so they don't interfere with default assertions
        let saved_token = std::env::var("PROVENANCE_API_TOKEN").ok();
        let saved_token_legacy = std::env::var("NETRISE_API_TOKEN").ok();
        let saved_url = std::env::var("PROVENANCE_API_URL").ok();
        let saved_url_legacy = std::env::var("NETRISE_API_URL").ok();
        std::env::remove_var("PROVENANCE_API_TOKEN");
        std::env::remove_var("NETRISE_API_TOKEN");
        std::env::remove_var("PROVENANCE_API_URL");
        std::env::remove_var("NETRISE_API_URL");

        let cfg = build_config(None, None, None, None, None, 0, false, false, false);
        assert!(cfg.token.is_none() || cfg.token.as_deref() == Some(""));
        assert_eq!(cfg.api_url, "https://provenance.netrise.io/v1/provenance");
        assert_eq!(cfg.concurrency, 10);
        assert_eq!(cfg.timeout, 30);

        // Restore env vars
        if let Some(t) = saved_token {
            std::env::set_var("PROVENANCE_API_TOKEN", t);
        }
        if let Some(t) = saved_token_legacy {
            std::env::set_var("NETRISE_API_TOKEN", t);
        }
        if let Some(u) = saved_url {
            std::env::set_var("PROVENANCE_API_URL", u);
        }
        if let Some(u) = saved_url_legacy {
            std::env::set_var("NETRISE_API_URL", u);
        }
    }

    #[test]
    fn test_build_config_overrides() {
        let cfg = build_config(
            Some("my-token"),
            Some("https://custom.api"),
            Some("json"),
            Some(5),
            Some(60),
            2,
            false,
            true,
            true,
        );
        assert_eq!(cfg.token.as_deref(), Some("my-token"));
        assert_eq!(cfg.api_url, "https://custom.api");
        assert_eq!(cfg.format, OutputFormat::Json);
        assert_eq!(cfg.concurrency, 5);
        assert_eq!(cfg.timeout, 60);
        assert!(cfg.no_color);
        assert!(cfg.ascii);
    }
}
