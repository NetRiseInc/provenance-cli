use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub metadata: PolicyMetadata,
    pub spec: PolicySpec,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolicyMetadata {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicySpec {
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub action: String,
    #[serde(default, rename = "match")]
    pub match_conditions: HashMap<String, serde_yaml::Value>,
}

impl PolicyFile {
    /// Validate the policy file structure and return errors.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.api_version != "netrise/v1" {
            errors.push(format!(
                "Unsupported apiVersion '{}', expected 'netrise/v1'",
                self.api_version
            ));
        }

        if self.kind != "Policy" {
            errors.push(format!(
                "Unsupported kind '{}', expected 'Policy'",
                self.kind
            ));
        }

        let valid_actions = ["info", "warn", "review", "deny", "allow"];
        let valid_conditions = [
            "contributor_countries",
            "has_breached_credentials",
            "advisory_relationship",
            "advisory_names",
            "bus_factor_below",
            "signed_commit_ratio_below",
            "repo_archived",
            "repo_deprecated",
            "scorecard_score_below",
            "no_recent_commits_days",
            "license_spdx",
            "key_change_detected",
            "package_purl",
            "contributor_emails",
            "repo_urls",
        ];

        for rule in &self.spec.rules {
            if !valid_actions.contains(&rule.action.as_str()) {
                errors.push(format!(
                    "Rule '{}': invalid action '{}'. Valid actions: {}",
                    rule.name,
                    rule.action,
                    valid_actions.join(", ")
                ));
            }

            for key in rule.match_conditions.keys() {
                if !valid_conditions.contains(&key.as_str()) {
                    errors.push(format!(
                        "Rule '{}': unknown condition '{}'. Valid conditions: {}",
                        rule.name,
                        key,
                        valid_conditions.join(", ")
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Parse a policy YAML string and validate.
pub fn parse_policy(content: &str) -> Result<PolicyFile, String> {
    let policy: PolicyFile =
        serde_yaml::from_str(content).map_err(|e| format!("YAML parse error: {}", e))?;

    policy.validate().map_err(|errors| errors.join("; "))?;

    Ok(policy)
}

/// Load all policy files from a list of paths and/or directories.
pub fn load_policies(
    policy_paths: &[String],
    policy_dir: Option<&str>,
) -> Result<Vec<PolicyFile>, String> {
    let mut policies = Vec::new();

    for path in policy_paths {
        let p = std::path::Path::new(path);
        if p.is_dir() {
            // If the path is a directory, load all .yaml/.yml files from it
            let entries = std::fs::read_dir(p)
                .map_err(|e| format!("Failed to read policy directory '{}': {}", path, e))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("Error reading directory entry: {}", e))?;
                let entry_path = entry.path();
                if let Some(ext) = entry_path.extension() {
                    let ext = ext.to_string_lossy().to_lowercase();
                    if ext == "yaml" || ext == "yml" {
                        let content = std::fs::read_to_string(&entry_path).map_err(|e| {
                            format!(
                                "Failed to read policy file '{}': {}",
                                entry_path.display(),
                                e
                            )
                        })?;
                        let policy = parse_policy(&content).map_err(|e| {
                            format!("Error in policy file '{}': {}", entry_path.display(), e)
                        })?;
                        policies.push(policy);
                    }
                }
            }
        } else {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read policy file '{}': {}", path, e))?;
            let policy = parse_policy(&content)
                .map_err(|e| format!("Error in policy file '{}': {}", path, e))?;
            policies.push(policy);
        }
    }

    if let Some(dir) = policy_dir {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("Failed to read policy directory '{}': {}", dir, e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Error reading directory entry: {}", e))?;
            let path = entry.path();
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "yaml" || ext == "yml" {
                    let content = std::fs::read_to_string(&path).map_err(|e| {
                        format!("Failed to read policy file '{}': {}", path.display(), e)
                    })?;
                    let policy = parse_policy(&content)
                        .map_err(|e| format!("Error in policy file '{}': {}", path.display(), e))?;
                    policies.push(policy);
                }
            }
        }
    }

    Ok(policies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_policy() {
        let yaml = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: test-policy
spec:
  rules:
    - name: deny-direct
      description: deny direct advisories
      action: deny
      match:
        advisory_relationship: direct
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.spec.rules.len(), 1);
        assert_eq!(policy.spec.rules[0].name, "deny-direct");
    }

    #[test]
    fn test_reject_invalid_action() {
        let yaml = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: bad
spec:
  rules:
    - name: bad-rule
      action: explode
      match:
        advisory_relationship: direct
"#;
        let result = parse_policy(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid action"));
    }

    #[test]
    fn test_reject_unknown_condition() {
        let yaml = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: bad
spec:
  rules:
    - name: bad-rule
      action: deny
      match:
        nonexistent_condition: true
"#;
        let result = parse_policy(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown condition"));
    }

    #[test]
    fn test_empty_rules_valid() {
        let yaml = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: empty
spec:
  rules: []
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.spec.rules.len(), 0);
    }

    #[test]
    fn test_load_policies_from_directory_path() {
        // Create a temp directory with a policy file
        let dir = std::env::temp_dir().join("provenance-test-policy-dir");
        std::fs::create_dir_all(&dir).unwrap();
        let policy_content = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: test
spec:
  rules:
    - name: test-rule
      action: warn
      match:
        advisory_relationship: direct
"#;
        std::fs::write(dir.join("test.yaml"), policy_content).unwrap();

        // load_policies should treat the directory path like --policy-dir
        let dir_str = dir.to_string_lossy().to_string();
        let policies = load_policies(&[dir_str], None).unwrap();
        assert!(!policies.is_empty());
        assert_eq!(policies[0].spec.rules[0].name, "test-rule");

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_all_valid_conditions() {
        let yaml = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: all-conditions
spec:
  rules:
    - name: test
      action: warn
      match:
        contributor_countries:
          - CN
        has_breached_credentials: true
        advisory_relationship: direct
        advisory_names:
          - "CVE-*"
        bus_factor_below: 2
        signed_commit_ratio_below: 0.5
        repo_archived: true
        repo_deprecated: true
        scorecard_score_below: 5.0
        no_recent_commits_days: 365
        license_spdx:
          - MIT
        key_change_detected: true
        package_purl: "pkg:deb/*"
        contributor_emails:
          - "*@gmail.com"
        repo_urls:
          - "*github.com/*"
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.spec.rules[0].match_conditions.len(), 15);
    }
}
