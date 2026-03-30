use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Package endpoint ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageResponse {
    pub purl: String,
    pub data: PackageData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageData {
    #[serde(default)]
    pub package_type: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub distro: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub package_details: Option<PackageDetails>,
    #[serde(default)]
    pub repository_details: Option<RepositoryDetails>,
    #[serde(default)]
    pub advisories: Vec<Advisory>,
    #[serde(default)]
    pub metadata: Option<Metadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub purl: String,
    #[serde(default)]
    pub depth: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageDetails {
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub released_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepositoryDetails {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub contributors: Vec<Contributor>,
    #[serde(default)]
    pub health_available: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Contributor {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub has_signed_commits: Option<bool>,
    #[serde(default)]
    pub has_unsigned_commits: Option<bool>,
    #[serde(default)]
    pub has_signing_key: Option<bool>,
    #[serde(default)]
    pub signed_commit_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub name: String,
    #[serde(default)]
    pub relationship: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub compiled_at: Option<String>,
}

// ── Package search endpoint ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSearchResponse {
    #[serde(default)]
    pub purls: Vec<String>,
}

// ── Package dependents endpoint ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDependentsResponse {
    #[serde(default)]
    pub purls: Vec<String>,
}

// ── Repo endpoint ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoResponse {
    pub repo: String,
    pub data: RepoData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoData {
    #[serde(default)]
    pub packages: Vec<RepoPackage>,
    #[serde(default)]
    pub contributors: Vec<Contributor>,
    #[serde(default)]
    pub advisories: Vec<Advisory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoPackage {
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub methods: Vec<String>,
}

// ── Repo health endpoint ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoHealthResponse {
    #[serde(default)]
    pub repo_url: Option<String>,
    pub data: RepoHealthData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoHealthData {
    #[serde(default)]
    pub activity: Option<Activity>,
    #[serde(default)]
    pub code_hygiene: Option<CodeHygiene>,
    #[serde(default)]
    pub contributor_risk: Option<ContributorRisk>,
    #[serde(default)]
    pub popularity: Option<serde_json::Value>,
    #[serde(default)]
    pub security_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Activity {
    #[serde(default)]
    pub commit_frequency: Option<CommitFrequency>,
    #[serde(default)]
    pub has_changelog: Option<bool>,
    #[serde(default)]
    pub has_readme: Option<bool>,
    #[serde(default)]
    pub is_archived: Option<bool>,
    #[serde(default)]
    pub is_deprecated: Option<bool>,
    #[serde(default)]
    pub issue_close_rate_180d: Option<f64>,
    #[serde(default)]
    pub last_commit_date: Option<String>,
    #[serde(default)]
    pub last_release_date: Option<String>,
    #[serde(default)]
    pub open_issues_count: Option<i64>,
    #[serde(default)]
    pub open_pr_count: Option<i64>,
    #[serde(default)]
    pub pr_merge_rate_180d: Option<f64>,
    #[serde(default)]
    pub release_cadence_days: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommitFrequency {
    #[serde(default)]
    pub days_90: Option<i64>,
    #[serde(default)]
    pub days_180: Option<i64>,
    #[serde(default)]
    pub days_365: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeHygiene {
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub has_gitignore: Option<bool>,
    #[serde(default)]
    pub has_lockfile: Option<bool>,
    #[serde(default)]
    pub is_fork: Option<bool>,
    #[serde(default)]
    pub license_spdx: Option<String>,
    #[serde(default)]
    pub parent_repo: Option<String>,
    #[serde(default)]
    pub repo_size_kb: Option<i64>,
    #[serde(default)]
    pub topics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContributorRisk {
    #[serde(default)]
    pub active_contributors_12mo: Option<i64>,
    #[serde(default)]
    pub bus_factor: Option<i64>,
    #[serde(default)]
    pub contributors_with_breached_creds: Option<i64>,
    #[serde(default)]
    pub maintainer_geo_distribution: Option<HashMap<String, i64>>,
}

// ── Contributor endpoint ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributorResponse {
    pub email: String,
    pub data: ContributorData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContributorData {
    #[serde(default)]
    pub summary: Option<ContributorSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContributorSummary {
    #[serde(default)]
    pub purls: Vec<String>,
    #[serde(default)]
    pub repos: Vec<String>,
}

// ── Contributor security endpoint ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributorSecurityResponse {
    pub email: String,
    pub data: ContributorSecurityData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContributorSecurityData {
    #[serde(default)]
    pub has_breached_credentials: Option<bool>,
    #[serde(default)]
    pub signed_commit_ratio: Option<f64>,
    #[serde(default)]
    pub signing_key_info: Option<SigningKeyInfo>,
    #[serde(default)]
    pub metadata: Option<Metadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigningKeyInfo {
    #[serde(default)]
    pub has_signing_key: Option<bool>,
    #[serde(default)]
    pub key_age_days: Option<i64>,
    #[serde(default)]
    pub key_change_detected: Option<bool>,
    #[serde(default)]
    pub key_changes: Vec<KeyChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyChange {
    #[serde(default)]
    pub detected_at: Option<String>,
    #[serde(default)]
    pub new_key_id: Option<String>,
    #[serde(default)]
    pub old_key_id: Option<String>,
}

// ── Advisory endpoint ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryResponse {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub repositories: Option<AdvisoryRelationships>,
    #[serde(default)]
    pub packages: Option<AdvisoryRelationships>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdvisoryRelationships {
    #[serde(default)]
    pub direct: Vec<serde_json::Value>,
    #[serde(default)]
    pub indirect: Vec<serde_json::Value>,
}
