use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub api_url: Option<String>,
    #[serde(default)]
    pub default_format: Option<String>,
    #[serde(default)]
    pub concurrency: Option<usize>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub token: Option<String>,
    pub api_url: String,
    pub format: OutputFormat,
    pub concurrency: usize,
    pub timeout: u64,
    pub verbose: u8,
    pub quiet: bool,
    pub no_color: bool,
    pub ascii: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Human => write!(f, "human"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "human" => Ok(OutputFormat::Human),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            _ => Err(format!(
                "unknown format '{}', expected: human, json, sarif",
                s
            )),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            token: None,
            api_url: "https://provenance.netrise.io/v1/provenance".to_string(),
            format: OutputFormat::Human,
            concurrency: 10,
            timeout: 30,
            verbose: 0,
            quiet: false,
            no_color: false,
            ascii: false,
        }
    }
}
