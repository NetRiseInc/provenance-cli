use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Authentication failed: invalid or missing API token. Set PROVENANCE_API_TOKEN environment variable or use --token flag. You can also set it in ~/.config/provenance/config.yaml")]
    Unauthorized,

    #[error(
        "Rate limited by API (429). Retry after {retry_after:?}s. Consider reducing --concurrency."
    )]
    RateLimited { retry_after: Option<u64> },

    #[error("API returned {status}: {body}")]
    HttpError { status: u16, body: String },

    #[error("Request timed out after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },

    #[error("Network error: {0}")]
    Network(String),

    #[error("Failed to parse API response: {0}")]
    Deserialization(String),

    #[error("API request failed: {0}")]
    Request(#[from] reqwest::Error),
}
