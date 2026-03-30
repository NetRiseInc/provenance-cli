use crate::policy::types::*;
use serde::Serialize;

#[derive(Serialize)]
pub struct JsonCheckOutput {
    pub verdict: String,
    pub exit_code: i32,
    pub rules_matched: Vec<JsonRuleMatch>,
    pub warnings: Vec<String>,
    pub metadata: JsonMetadata,
}

#[derive(Serialize)]
pub struct JsonRuleMatch {
    pub rule: String,
    pub description: String,
    pub action: String,
    pub purl: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct JsonMetadata {
    pub timestamp: String,
    pub version: String,
    pub api_url: String,
}

impl JsonCheckOutput {
    pub fn from_aggregate(result: &AggregateCheckResult, api_url: &str) -> Self {
        Self {
            verdict: result.overall_verdict.to_string(),
            exit_code: result.overall_verdict.exit_code(),
            rules_matched: result
                .all_matches
                .iter()
                .map(|m| JsonRuleMatch {
                    rule: m.rule_name.clone(),
                    description: m.rule_description.clone(),
                    action: m.action.to_string(),
                    purl: m.purl.clone(),
                    reason: m.reason.clone(),
                })
                .collect(),
            warnings: result.warnings.clone(),
            metadata: JsonMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                api_url: api_url.to_string(),
            },
        }
    }
}

#[derive(Serialize)]
pub struct JsonScanOutput {
    pub total_packages: usize,
    pub scanned: usize,
    pub failed: usize,
    pub packages_with_advisories: usize,
    pub packages: Vec<JsonPackageSummary>,
    pub errors: Vec<String>,
    pub metadata: JsonMetadata,
}

#[derive(Serialize)]
pub struct JsonPackageSummary {
    pub purl: String,
    pub advisories: Vec<JsonAdvisory>,
    pub repo_url: Option<String>,
}

#[derive(Serialize)]
pub struct JsonAdvisory {
    pub name: String,
    pub relationship: Option<String>,
}

/// Combined scan + policy evaluation output as a single JSON document
#[derive(Serialize)]
pub struct JsonScanWithPolicyOutput {
    pub scan: JsonScanOutput,
    pub policy: JsonCheckOutput,
}
