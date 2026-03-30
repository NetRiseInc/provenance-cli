use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Info,
    Warn,
    Review,
    Deny,
    Allow,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Info => write!(f, "INFO"),
            Action::Warn => write!(f, "WARN"),
            Action::Review => write!(f, "REVIEW"),
            Action::Deny => write!(f, "DENY"),
            Action::Allow => write!(f, "ALLOW"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_name: String,
    pub rule_description: String,
    pub action: Action,
    pub reason: String,
    pub purl: String,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub verdict: Verdict,
    pub matches: Vec<RuleMatch>,
    pub warnings: Vec<String>,
    #[allow(dead_code)]
    pub purl: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Pass,
    Deny,
    Review,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Pass => write!(f, "PASS"),
            Verdict::Deny => write!(f, "DENY"),
            Verdict::Review => write!(f, "REVIEW"),
        }
    }
}

impl Verdict {
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Pass => 0,
            Verdict::Deny => 1,
            Verdict::Review => 2,
        }
    }
}

/// Aggregate multiple per-package check results into an overall verdict.
#[derive(Debug, Clone)]
pub struct AggregateCheckResult {
    pub overall_verdict: Verdict,
    pub package_results: Vec<CheckResult>,
    pub all_matches: Vec<RuleMatch>,
    pub warnings: Vec<String>,
}

impl AggregateCheckResult {
    pub fn from_results(results: Vec<CheckResult>) -> Self {
        let mut overall = Verdict::Pass;
        let mut all_matches = Vec::new();
        let mut warnings = Vec::new();

        let mut seen_warnings = HashSet::new();

        for r in &results {
            match r.verdict {
                Verdict::Deny => overall = Verdict::Deny,
                Verdict::Review if overall != Verdict::Deny => overall = Verdict::Review,
                _ => {}
            }
            all_matches.extend(r.matches.clone());
            for w in &r.warnings {
                if seen_warnings.insert(w.clone()) {
                    warnings.push(w.clone());
                }
            }
        }

        Self {
            overall_verdict: overall,
            package_results: results,
            all_matches,
            warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_exit_codes() {
        assert_eq!(Verdict::Pass.exit_code(), 0);
        assert_eq!(Verdict::Deny.exit_code(), 1);
        assert_eq!(Verdict::Review.exit_code(), 2);
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(Verdict::Pass.to_string(), "PASS");
        assert_eq!(Verdict::Deny.to_string(), "DENY");
        assert_eq!(Verdict::Review.to_string(), "REVIEW");
    }

    #[test]
    fn test_action_display() {
        assert_eq!(Action::Info.to_string(), "INFO");
        assert_eq!(Action::Warn.to_string(), "WARN");
        assert_eq!(Action::Review.to_string(), "REVIEW");
        assert_eq!(Action::Deny.to_string(), "DENY");
        assert_eq!(Action::Allow.to_string(), "ALLOW");
    }

    #[test]
    fn test_aggregate_empty_results() {
        let agg = AggregateCheckResult::from_results(vec![]);
        assert_eq!(agg.overall_verdict, Verdict::Pass);
        assert!(agg.all_matches.is_empty());
    }

    #[test]
    fn test_aggregate_deny_wins() {
        let results = vec![
            CheckResult {
                verdict: Verdict::Review,
                matches: vec![],
                warnings: vec![],
                purl: "pkg:a".to_string(),
            },
            CheckResult {
                verdict: Verdict::Deny,
                matches: vec![],
                warnings: vec![],
                purl: "pkg:b".to_string(),
            },
        ];
        let agg = AggregateCheckResult::from_results(results);
        assert_eq!(agg.overall_verdict, Verdict::Deny);
    }

    #[test]
    fn test_aggregate_review_if_no_deny() {
        let results = vec![
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec![],
                purl: "pkg:a".to_string(),
            },
            CheckResult {
                verdict: Verdict::Review,
                matches: vec![],
                warnings: vec![],
                purl: "pkg:b".to_string(),
            },
        ];
        let agg = AggregateCheckResult::from_results(results);
        assert_eq!(agg.overall_verdict, Verdict::Review);
    }

    #[test]
    fn test_aggregate_pass_if_only_pass() {
        let results = vec![
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec![],
                purl: "pkg:a".to_string(),
            },
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec![],
                purl: "pkg:b".to_string(),
            },
        ];
        let agg = AggregateCheckResult::from_results(results);
        assert_eq!(agg.overall_verdict, Verdict::Pass);
    }

    #[test]
    fn test_aggregate_collects_matches() {
        let results = vec![CheckResult {
            verdict: Verdict::Deny,
            matches: vec![RuleMatch {
                rule_name: "test-rule".to_string(),
                rule_description: "desc".to_string(),
                action: Action::Deny,
                reason: "because".to_string(),
                purl: "pkg:a".to_string(),
            }],
            warnings: vec!["a warning".to_string()],
            purl: "pkg:a".to_string(),
        }];
        let agg = AggregateCheckResult::from_results(results);
        assert_eq!(agg.all_matches.len(), 1);
        assert_eq!(agg.warnings.len(), 1);
    }

    #[test]
    fn test_aggregate_deduplicates_warnings() {
        let results = vec![
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec![
                    "Health data unavailable; bus_factor_below skipped".to_string(),
                    "Health data unavailable; repo_archived skipped".to_string(),
                ],
                purl: "pkg:a".to_string(),
            },
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec![
                    "Health data unavailable; bus_factor_below skipped".to_string(),
                    "Health data unavailable; repo_archived skipped".to_string(),
                ],
                purl: "pkg:b".to_string(),
            },
        ];
        let agg = AggregateCheckResult::from_results(results);
        assert_eq!(agg.warnings.len(), 2);
        assert_eq!(
            agg.warnings[0],
            "Health data unavailable; bus_factor_below skipped"
        );
        assert_eq!(
            agg.warnings[1],
            "Health data unavailable; repo_archived skipped"
        );
    }

    #[test]
    fn test_aggregate_preserves_unique_warnings() {
        let results = vec![
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec!["warning A".to_string()],
                purl: "pkg:a".to_string(),
            },
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec!["warning B".to_string()],
                purl: "pkg:b".to_string(),
            },
        ];
        let agg = AggregateCheckResult::from_results(results);
        assert_eq!(agg.warnings.len(), 2);
        assert!(agg.warnings.contains(&"warning A".to_string()));
        assert!(agg.warnings.contains(&"warning B".to_string()));
    }

    #[test]
    fn test_aggregate_preserves_warning_order() {
        let results = vec![
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec!["first".to_string(), "second".to_string()],
                purl: "pkg:a".to_string(),
            },
            CheckResult {
                verdict: Verdict::Pass,
                matches: vec![],
                warnings: vec!["second".to_string(), "third".to_string()],
                purl: "pkg:b".to_string(),
            },
        ];
        let agg = AggregateCheckResult::from_results(results);
        assert_eq!(agg.warnings.len(), 3);
        assert_eq!(agg.warnings[0], "first");
        assert_eq!(agg.warnings[1], "second");
        assert_eq!(agg.warnings[2], "third");
    }
}
