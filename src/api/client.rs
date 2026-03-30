use crate::api::error::ApiError;
use crate::api::types::*;
use crate::sbom::normalize_purl;
use reqwest::{Client, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

const USER_AGENT: &str = concat!("provenance-cli/", env!("CARGO_PKG_VERSION"));

pub struct ApiClient {
    client: Client,
    base_url: String,
    token: String,
    semaphore: Arc<Semaphore>,
    max_retries: u32,
    verbose: u8,
}

impl ApiClient {
    pub fn new(
        base_url: &str,
        token: &str,
        timeout_secs: u64,
        concurrency: usize,
        verbose: u8,
    ) -> Result<Self, ApiError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent(USER_AGENT)
            .build()
            .map_err(ApiError::Request)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            semaphore: Arc::new(Semaphore::new(concurrency)),
            max_retries: 3,
            verbose,
        })
    }

    async fn get_with_retry(&self, url: &str) -> Result<String, ApiError> {
        // Acquire the semaphore permit per-attempt, not for the whole retry loop.
        // This prevents semaphore starvation: when a request gets a 429 and sleeps
        // for exponential backoff, the permit is released so other futures can proceed.
        let mut last_error = None;
        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                // Sleep BEFORE acquiring the permit so we don't hold it during backoff
                let delay = Duration::from_millis(1000 * 2u64.pow(attempt - 1));
                tokio::time::sleep(delay).await;
            }

            let _permit = self.semaphore.acquire().await.unwrap();

            if self.verbose >= 2 {
                eprintln!("[DEBUG] GET {} (attempt {})", url, attempt + 1);
            }

            let result = self
                .client
                .get(url)
                .header("Authorization", format!("Bearer {}", self.token))
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if self.verbose >= 2 {
                        eprintln!("[DEBUG] Response status: {}", status.as_u16());
                    }

                    match status {
                        StatusCode::OK => {
                            let body = response.text().await.map_err(ApiError::Request)?;
                            return Ok(body);
                        }
                        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                            return Err(ApiError::Unauthorized);
                        }
                        StatusCode::TOO_MANY_REQUESTS => {
                            let retry_after = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok());
                            last_error = Some(ApiError::RateLimited { retry_after });
                            // _permit drops here, releasing before the next iteration's sleep
                            continue;
                        }
                        s if s.is_server_error() => {
                            let body = response
                                .text()
                                .await
                                .unwrap_or_else(|_| "unknown".to_string());
                            last_error = Some(ApiError::HttpError {
                                status: s.as_u16(),
                                body,
                            });
                            // _permit drops here, releasing before the next iteration's sleep
                            continue;
                        }
                        _ => {
                            let body = response
                                .text()
                                .await
                                .unwrap_or_else(|_| "unknown".to_string());
                            return Err(ApiError::HttpError {
                                status: status.as_u16(),
                                body,
                            });
                        }
                    }
                }
                Err(e) => {
                    if e.is_timeout() {
                        last_error = Some(ApiError::Timeout { timeout_secs: 30 });
                        // _permit drops here, releasing before the next iteration's sleep
                        continue;
                    }
                    return Err(ApiError::Network(e.to_string()));
                }
            }
        }

        Err(last_error.unwrap_or(ApiError::Network("unknown error".to_string())))
    }

    pub async fn get_package(&self, purl: &str) -> Result<PackageResponse, ApiError> {
        let normalized = normalize_purl(purl);
        let url = format!(
            "{}/package?identifier={}",
            self.base_url,
            urlencoding::encode(&normalized)
        );
        let body = self.get_with_retry(&url).await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Deserialization(e.to_string()))
    }

    pub async fn search_package(&self, purl: &str) -> Result<PackageSearchResponse, ApiError> {
        let normalized = normalize_purl(purl);
        let url = format!(
            "{}/package/search?identifier={}",
            self.base_url,
            urlencoding::encode(&normalized)
        );
        let body = self.get_with_retry(&url).await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Deserialization(e.to_string()))
    }

    pub async fn get_package_dependents(
        &self,
        purl: &str,
    ) -> Result<PackageDependentsResponse, ApiError> {
        let normalized = normalize_purl(purl);
        let url = format!(
            "{}/package/dependents?identifier={}",
            self.base_url,
            urlencoding::encode(&normalized)
        );
        let body = self.get_with_retry(&url).await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Deserialization(e.to_string()))
    }

    pub async fn get_repo(&self, repo_url: &str) -> Result<RepoResponse, ApiError> {
        let url = format!(
            "{}/repo?repo_url={}",
            self.base_url,
            urlencoding::encode(repo_url)
        );
        let body = self.get_with_retry(&url).await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Deserialization(e.to_string()))
    }

    pub async fn get_repo_health(&self, repo_url: &str) -> Result<RepoHealthResponse, ApiError> {
        let url = format!(
            "{}/repo/health?repo_url={}",
            self.base_url,
            urlencoding::encode(repo_url)
        );
        let body = self.get_with_retry(&url).await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Deserialization(e.to_string()))
    }

    pub async fn get_contributor(&self, identifier: &str) -> Result<ContributorResponse, ApiError> {
        let param = if identifier.contains('@') {
            format!("email={}", urlencoding::encode(identifier))
        } else {
            format!("username={}", urlencoding::encode(identifier))
        };
        let url = format!("{}/contributor?{}", self.base_url, param);
        let body = self.get_with_retry(&url).await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Deserialization(e.to_string()))
    }

    pub async fn get_contributor_security(
        &self,
        email: &str,
    ) -> Result<ContributorSecurityResponse, ApiError> {
        let url = format!(
            "{}/contributor/security?email={}",
            self.base_url,
            urlencoding::encode(email)
        );
        let body = self.get_with_retry(&url).await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Deserialization(e.to_string()))
    }

    pub async fn get_advisory(&self, advisory_id: &str) -> Result<AdvisoryResponse, ApiError> {
        let url = format!(
            "{}/advisory?advisory_id={}",
            self.base_url,
            urlencoding::encode(advisory_id)
        );
        let body = self.get_with_retry(&url).await?;
        serde_json::from_str(&body).map_err(|e| ApiError::Deserialization(e.to_string()))
    }

    /// Simple connectivity test — queries a known endpoint and checks for a non-error response.
    /// Uses a known-good PURL with full qualifiers.
    pub async fn test_connectivity(&self) -> Result<(), ApiError> {
        let url = format!(
            "{}/package/search?identifier={}",
            self.base_url,
            urlencoding::encode(
                "pkg:deb/debian/xz-utils@5.0.0-2?arch=kfreebsd-amd64&distro=debian-6"
            )
        );
        // For connectivity test, we just need the API to accept our auth.
        // A 404 with a JSON body means auth worked but no results (still a successful test).
        let _permit = self.semaphore.acquire().await.unwrap();

        let result = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await;

        match result {
            Ok(response) => {
                let status = response.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return Err(ApiError::Unauthorized);
                }
                // Any other response (200, 404, etc.) means the API is reachable and auth worked
                Ok(())
            }
            Err(e) => {
                if e.is_timeout() {
                    Err(ApiError::Timeout { timeout_secs: 30 })
                } else {
                    Err(ApiError::Network(e.to_string()))
                }
            }
        }
    }
}
