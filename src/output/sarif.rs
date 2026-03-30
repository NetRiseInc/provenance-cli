use crate::api::types::*;
use crate::policy::types::*;
use serde::Serialize;

/// SARIF v2.1.0 output
#[derive(Serialize)]
pub struct SarifOutput {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Serialize, Clone)]
pub struct SarifRule {
    pub id: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
}

#[derive(Serialize, Clone)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Serialize, Clone)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Serialize, Clone)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Serialize, Clone)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    #[serde(rename = "logicalLocations", skip_serializing_if = "Vec::is_empty")]
    pub logical_locations: Vec<SarifLogicalLocation>,
}

#[derive(Serialize, Clone)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Serialize, Clone)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Serialize, Clone)]
pub struct SarifLogicalLocation {
    pub name: String,
    #[serde(rename = "fullyQualifiedName")]
    pub fully_qualified_name: String,
    pub kind: String,
}

/// Create a SARIF location using a file-scheme URI for the physical location
/// and the PURL/entity as a logical location. GitHub Code Scanning requires
/// file-scheme URIs in physicalLocation.
fn make_location(purl_or_entity: &str) -> Vec<SarifLocation> {
    vec![SarifLocation {
        physical_location: SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: "provenance-results.sarif".to_string(),
            },
        },
        logical_locations: vec![SarifLogicalLocation {
            name: purl_or_entity.to_string(),
            fully_qualified_name: purl_or_entity.to_string(),
            kind: "package".to_string(),
        }],
    }]
}

fn action_to_sarif_level(action: &Action) -> &'static str {
    match action {
        Action::Deny => "error",
        Action::Review => "warning",
        Action::Warn => "note",
        Action::Info => "none",
        Action::Allow => "none",
    }
}

impl SarifOutput {
    /// Create an empty SARIF document (valid, with tool info but no findings).
    pub fn empty() -> Self {
        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules: vec![],
                    },
                },
                results: vec![],
            }],
        }
    }

    /// Create SARIF output from a package query response.
    pub fn from_package(resp: &PackageResponse) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        // Each advisory becomes a finding
        for adv in &resp.data.advisories {
            let rule_id = format!("advisory/{}", adv.name);
            let level = match adv.relationship.as_deref() {
                Some("direct") => "warning",
                Some("indirect") => "note",
                _ => "note",
            };

            if seen_rules.insert(rule_id.clone()) {
                rules.push(SarifRule {
                    id: rule_id.clone(),
                    short_description: SarifMessage {
                        text: format!("Advisory: {}", adv.name),
                    },
                    full_description: SarifMessage {
                        text: format!(
                            "Advisory {} ({} relationship)",
                            adv.name,
                            adv.relationship.as_deref().unwrap_or("unknown")
                        ),
                    },
                    default_configuration: SarifConfiguration {
                        level: level.to_string(),
                    },
                });
            }

            results.push(SarifResult {
                rule_id: rule_id.clone(),
                level: level.to_string(),
                message: SarifMessage {
                    text: format!(
                        "{}: advisory {} ({})",
                        resp.purl,
                        adv.name,
                        adv.relationship.as_deref().unwrap_or("unknown")
                    ),
                },
                locations: make_location(&resp.purl),
            });
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Create SARIF output from a package search response.
    pub fn from_package_search(resp: &PackageSearchResponse, query_purl: &str) -> Self {
        let mut results = Vec::new();
        let rules = if resp.purls.is_empty() {
            vec![]
        } else {
            vec![SarifRule {
                id: "package-search/match".to_string(),
                short_description: SarifMessage {
                    text: "Package search match".to_string(),
                },
                full_description: SarifMessage {
                    text: format!("Package found matching search for {}", query_purl),
                },
                default_configuration: SarifConfiguration {
                    level: "none".to_string(),
                },
            }]
        };

        for purl in &resp.purls {
            results.push(SarifResult {
                rule_id: "package-search/match".to_string(),
                level: "none".to_string(),
                message: SarifMessage {
                    text: format!("Search match: {}", purl),
                },
                locations: make_location(purl),
            });
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Create SARIF output from a package dependents response.
    pub fn from_package_dependents(resp: &PackageDependentsResponse, query_purl: &str) -> Self {
        let mut results = Vec::new();
        let rules = if resp.purls.is_empty() {
            vec![]
        } else {
            vec![SarifRule {
                id: "package-dependents/match".to_string(),
                short_description: SarifMessage {
                    text: "Package dependent".to_string(),
                },
                full_description: SarifMessage {
                    text: format!("Package that depends on {}", query_purl),
                },
                default_configuration: SarifConfiguration {
                    level: "none".to_string(),
                },
            }]
        };

        for purl in &resp.purls {
            results.push(SarifResult {
                rule_id: "package-dependents/match".to_string(),
                level: "none".to_string(),
                message: SarifMessage {
                    text: format!("Dependent: {}", purl),
                },
                locations: make_location(purl),
            });
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Create SARIF output from a repo query response.
    pub fn from_repo(resp: &RepoResponse) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        for adv in &resp.data.advisories {
            let rule_id = format!("advisory/{}", adv.name);
            let level = match adv.relationship.as_deref() {
                Some("direct") => "warning",
                _ => "note",
            };

            if seen_rules.insert(rule_id.clone()) {
                rules.push(SarifRule {
                    id: rule_id.clone(),
                    short_description: SarifMessage {
                        text: format!("Advisory: {}", adv.name),
                    },
                    full_description: SarifMessage {
                        text: format!(
                            "Advisory {} ({} relationship)",
                            adv.name,
                            adv.relationship.as_deref().unwrap_or("unknown")
                        ),
                    },
                    default_configuration: SarifConfiguration {
                        level: level.to_string(),
                    },
                });
            }

            results.push(SarifResult {
                rule_id,
                level: level.to_string(),
                message: SarifMessage {
                    text: format!(
                        "{}: advisory {} ({})",
                        resp.repo,
                        adv.name,
                        adv.relationship.as_deref().unwrap_or("unknown")
                    ),
                },
                locations: make_location(&resp.repo),
            });
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Create SARIF output from a contributor query response.
    pub fn from_contributor(resp: &ContributorResponse) -> Self {
        let mut results = Vec::new();
        let mut rules = Vec::new();

        if let Some(ref summary) = resp.data.summary {
            if !summary.repos.is_empty() {
                rules.push(SarifRule {
                    id: "contributor/repo".to_string(),
                    short_description: SarifMessage {
                        text: "Contributor repository".to_string(),
                    },
                    full_description: SarifMessage {
                        text: format!("Repository associated with contributor {}", resp.email),
                    },
                    default_configuration: SarifConfiguration {
                        level: "none".to_string(),
                    },
                });

                for repo in &summary.repos {
                    results.push(SarifResult {
                        rule_id: "contributor/repo".to_string(),
                        level: "none".to_string(),
                        message: SarifMessage {
                            text: format!("Contributor {} contributes to {}", resp.email, repo),
                        },
                        locations: make_location(repo),
                    });
                }
            }
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Create SARIF output from a contributor security response.
    pub fn from_contributor_security(resp: &ContributorSecurityResponse) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();

        if let Some(true) = resp.data.has_breached_credentials {
            rules.push(SarifRule {
                id: "contributor-security/breached-credentials".to_string(),
                short_description: SarifMessage {
                    text: "Breached credentials detected".to_string(),
                },
                full_description: SarifMessage {
                    text: "Contributor has been found in credential breach databases".to_string(),
                },
                default_configuration: SarifConfiguration {
                    level: "warning".to_string(),
                },
            });
            results.push(SarifResult {
                rule_id: "contributor-security/breached-credentials".to_string(),
                level: "warning".to_string(),
                message: SarifMessage {
                    text: format!("Contributor {} has breached credentials", resp.email),
                },
                locations: make_location(&resp.email),
            });
        }

        if let Some(ref ski) = resp.data.signing_key_info {
            if let Some(true) = ski.key_change_detected {
                rules.push(SarifRule {
                    id: "contributor-security/key-change".to_string(),
                    short_description: SarifMessage {
                        text: "Signing key change detected".to_string(),
                    },
                    full_description: SarifMessage {
                        text: "Contributor's signing key has been changed".to_string(),
                    },
                    default_configuration: SarifConfiguration {
                        level: "note".to_string(),
                    },
                });
                results.push(SarifResult {
                    rule_id: "contributor-security/key-change".to_string(),
                    level: "note".to_string(),
                    message: SarifMessage {
                        text: format!("Contributor {} has a signing key change", resp.email),
                    },
                    locations: make_location(&resp.email),
                });
            }
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Create SARIF output from an advisory query response.
    pub fn from_advisory(resp: &AdvisoryResponse) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();

        let rule_id = format!("advisory/{}", resp.name);
        rules.push(SarifRule {
            id: rule_id.clone(),
            short_description: SarifMessage {
                text: format!("Advisory: {}", resp.name),
            },
            full_description: SarifMessage {
                text: format!(
                    "Advisory {} ({})",
                    resp.name,
                    resp.url.as_deref().unwrap_or("no URL")
                ),
            },
            default_configuration: SarifConfiguration {
                level: "warning".to_string(),
            },
        });

        // Add direct packages as findings
        if let Some(ref pkgs) = resp.packages {
            for p in &pkgs.direct {
                let pkg_str = p.as_str().unwrap_or(&p.to_string()).to_string();
                results.push(SarifResult {
                    rule_id: rule_id.clone(),
                    level: "warning".to_string(),
                    message: SarifMessage {
                        text: format!("Advisory {} directly affects {}", resp.name, pkg_str),
                    },
                    locations: make_location(&pkg_str),
                });
            }
            for p in &pkgs.indirect {
                let pkg_str = p.as_str().unwrap_or(&p.to_string()).to_string();
                results.push(SarifResult {
                    rule_id: rule_id.clone(),
                    level: "note".to_string(),
                    message: SarifMessage {
                        text: format!("Advisory {} indirectly affects {}", resp.name, pkg_str),
                    },
                    locations: make_location(&pkg_str),
                });
            }
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Create SARIF output from scan results (list of package responses).
    pub fn from_scan_results(results_list: &[(String, PackageResponse)]) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        for (purl, resp) in results_list {
            for adv in &resp.data.advisories {
                let rule_id = format!("advisory/{}", adv.name);
                let level = match adv.relationship.as_deref() {
                    Some("direct") => "warning",
                    Some("indirect") => "note",
                    _ => "note",
                };

                if seen_rules.insert(rule_id.clone()) {
                    rules.push(SarifRule {
                        id: rule_id.clone(),
                        short_description: SarifMessage {
                            text: format!("Advisory: {}", adv.name),
                        },
                        full_description: SarifMessage {
                            text: format!(
                                "Advisory {} ({} relationship)",
                                adv.name,
                                adv.relationship.as_deref().unwrap_or("unknown")
                            ),
                        },
                        default_configuration: SarifConfiguration {
                            level: level.to_string(),
                        },
                    });
                }

                results.push(SarifResult {
                    rule_id,
                    level: level.to_string(),
                    message: SarifMessage {
                        text: format!(
                            "{}: advisory {} ({})",
                            purl,
                            adv.name,
                            adv.relationship.as_deref().unwrap_or("unknown")
                        ),
                    },
                    locations: make_location(purl),
                });
            }
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    pub fn from_aggregate(result: &AggregateCheckResult) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        for m in &result.all_matches {
            if m.action == Action::Allow {
                continue;
            }

            if seen_rules.insert(m.rule_name.clone()) {
                rules.push(SarifRule {
                    id: m.rule_name.clone(),
                    short_description: SarifMessage {
                        text: m.rule_description.clone(),
                    },
                    full_description: SarifMessage {
                        text: m.rule_description.clone(),
                    },
                    default_configuration: SarifConfiguration {
                        level: action_to_sarif_level(&m.action).to_string(),
                    },
                });
            }

            results.push(SarifResult {
                rule_id: m.rule_name.clone(),
                level: action_to_sarif_level(&m.action).to_string(),
                message: SarifMessage {
                    text: format!("{}: {}", m.purl, m.reason),
                },
                locations: make_location(&m.purl),
            });
        }

        SarifOutput {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "provenance".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://provenance.netrise.io".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_version() {
        let agg = AggregateCheckResult::from_results(vec![]);
        let sarif = SarifOutput::from_aggregate(&agg);
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.name, "provenance");
    }

    #[test]
    fn test_sarif_level_mapping() {
        assert_eq!(action_to_sarif_level(&Action::Deny), "error");
        assert_eq!(action_to_sarif_level(&Action::Review), "warning");
        assert_eq!(action_to_sarif_level(&Action::Warn), "note");
        assert_eq!(action_to_sarif_level(&Action::Info), "none");
    }

    #[test]
    fn test_sarif_with_findings() {
        let results = vec![CheckResult {
            verdict: Verdict::Deny,
            matches: vec![
                RuleMatch {
                    rule_name: "deny-rule".to_string(),
                    rule_description: "a deny rule".to_string(),
                    action: Action::Deny,
                    reason: "matched".to_string(),
                    purl: "pkg:test@1.0".to_string(),
                },
                RuleMatch {
                    rule_name: "warn-rule".to_string(),
                    rule_description: "a warn rule".to_string(),
                    action: Action::Warn,
                    reason: "also matched".to_string(),
                    purl: "pkg:test@1.0".to_string(),
                },
            ],
            warnings: vec![],
            purl: "pkg:test@1.0".to_string(),
        }];
        let agg = AggregateCheckResult::from_results(results);
        let sarif = SarifOutput::from_aggregate(&agg);
        assert_eq!(sarif.runs[0].results.len(), 2);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 2);
        assert_eq!(sarif.runs[0].results[0].level, "error");
        assert_eq!(sarif.runs[0].results[1].level, "note");
    }

    #[test]
    fn test_sarif_skips_allow() {
        let results = vec![CheckResult {
            verdict: Verdict::Pass,
            matches: vec![RuleMatch {
                rule_name: "allow-rule".to_string(),
                rule_description: "an allow rule".to_string(),
                action: Action::Allow,
                reason: "allowed".to_string(),
                purl: "pkg:test@1.0".to_string(),
            }],
            warnings: vec![],
            purl: "pkg:test@1.0".to_string(),
        }];
        let agg = AggregateCheckResult::from_results(results);
        let sarif = SarifOutput::from_aggregate(&agg);
        assert_eq!(sarif.runs[0].results.len(), 0);
    }

    #[test]
    fn test_sarif_serialization() {
        let agg = AggregateCheckResult::from_results(vec![]);
        let sarif = SarifOutput::from_aggregate(&agg);
        let json = serde_json::to_string(&sarif).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["runs"].is_array());
    }

    #[test]
    fn test_sarif_empty() {
        let sarif = SarifOutput::empty();
        let json = serde_json::to_string(&sarif).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "provenance");
    }

    #[test]
    fn test_sarif_from_package() {
        let resp = PackageResponse {
            purl: "pkg:deb/debian/curl@7.68.0".to_string(),
            data: PackageData {
                advisories: vec![
                    Advisory {
                        name: "NETR-2024-0001".to_string(),
                        relationship: Some("direct".to_string()),
                    },
                    Advisory {
                        name: "NETR-2024-0002".to_string(),
                        relationship: Some("indirect".to_string()),
                    },
                ],
                ..Default::default()
            },
        };
        let sarif = SarifOutput::from_package(&resp);
        assert_eq!(sarif.runs[0].results.len(), 2);
        assert_eq!(sarif.runs[0].results[0].level, "warning"); // direct
        assert_eq!(sarif.runs[0].results[1].level, "note"); // indirect
    }

    #[test]
    fn test_sarif_from_package_no_advisories() {
        let resp = PackageResponse {
            purl: "pkg:deb/debian/curl@7.68.0".to_string(),
            data: PackageData::default(),
        };
        let sarif = SarifOutput::from_package(&resp);
        assert_eq!(sarif.runs[0].results.len(), 0);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 0);
        // SARIF should still be valid
        let json = serde_json::to_string(&sarif).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
    }

    #[test]
    fn test_sarif_from_scan_results() {
        let results = vec![
            (
                "pkg:deb/debian/curl@7.68.0".to_string(),
                PackageResponse {
                    purl: "pkg:deb/debian/curl@7.68.0".to_string(),
                    data: PackageData {
                        advisories: vec![Advisory {
                            name: "NETR-2024-0001".to_string(),
                            relationship: Some("direct".to_string()),
                        }],
                        ..Default::default()
                    },
                },
            ),
            (
                "pkg:npm/lodash@4.17.21".to_string(),
                PackageResponse {
                    purl: "pkg:npm/lodash@4.17.21".to_string(),
                    data: PackageData::default(),
                },
            ),
        ];
        let sarif = SarifOutput::from_scan_results(&results);
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert!(sarif.runs[0].results[0]
            .message
            .text
            .contains("pkg:deb/debian/curl"));
    }
}
