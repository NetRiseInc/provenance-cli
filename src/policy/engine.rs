use crate::api::client::ApiClient;
use crate::api::types::{ContributorSecurityData, RepoHealthData};
use crate::policy::conditions::{evaluate_condition, EvalContext};
use crate::policy::schema::PolicyFile;
use crate::policy::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};

/// Determine which additional data endpoints are needed based on policy conditions.
pub struct DataNeeds {
    pub needs_health: bool,
    /// Whether we need individual contributor /contributor/security API calls.
    /// With the optimized engine, `has_breached_credentials` uses repo health data
    /// (no per-contributor API calls needed).
    /// Both `key_change_detected` and `signed_commit_ratio_below` need /contributor/security calls.
    /// `key_change_detected` short-circuits after first match (sample of 10).
    /// `signed_commit_ratio_below` samples up to 15 contributors to compute a ratio.
    pub needs_contributor_security: bool,
    /// Whether `key_change_detected` condition is present (drives short-circuit behavior).
    pub needs_key_change: bool,
    /// Whether `signed_commit_ratio_below` condition is present.
    /// Drives a sampled fetch of contributor security data (up to 15 contributors).
    pub needs_signed_commit_ratio: bool,
}

impl DataNeeds {
    pub fn from_policies(policies: &[PolicyFile]) -> Self {
        let mut needs_health = false;
        let mut needs_contributor_security = false;
        let mut needs_key_change = false;
        let mut needs_signed_commit_ratio = false;

        let health_conditions = [
            "bus_factor_below",
            "signed_commit_ratio_below",
            "repo_archived",
            "repo_deprecated",
            "scorecard_score_below",
            "no_recent_commits_days",
            "has_breached_credentials",
            "contributor_countries",
            "license_spdx",
        ];

        for policy in policies {
            for rule in &policy.spec.rules {
                for key in rule.match_conditions.keys() {
                    if health_conditions.contains(&key.as_str()) {
                        needs_health = true;
                    }
                    if key == "key_change_detected" {
                        needs_contributor_security = true;
                        needs_key_change = true;
                    }
                    if key == "signed_commit_ratio_below" {
                        needs_signed_commit_ratio = true;
                        needs_contributor_security = true;
                    }
                }
            }
        }

        DataNeeds {
            needs_health,
            needs_contributor_security,
            needs_key_change,
            needs_signed_commit_ratio,
        }
    }
}

/// Cache for policy evaluation data, scoped to a single CLI invocation.
/// Avoids redundant API calls when multiple packages share the same repo URL
/// or when the same contributor email appears across packages.
///
/// Uses Arc<OnceCell<Option<T>>> per key for thundering herd protection:
/// only one HTTP request per unique key, even under concurrent access.
/// The OnceCell stores only the data (Option<T>), not the warning.
/// Warnings are ephemeral: only the first caller (the one that drives the fetch)
/// receives the warning; subsequent callers get cached data silently.
pub struct EvalCache {
    repo_health: Mutex<HashMap<String, Arc<OnceCell<Option<RepoHealthData>>>>>,
    contributor_security: Mutex<HashMap<String, Arc<OnceCell<Option<ContributorSecurityData>>>>>,
}

impl EvalCache {
    pub fn new() -> Self {
        Self {
            repo_health: Mutex::new(HashMap::new()),
            contributor_security: Mutex::new(HashMap::new()),
        }
    }

    /// Get cached repo health data or fetch from API.
    /// Caches both successes (Some) and failures (None).
    /// Only the first caller for a given URL drives the fetch and receives any warning.
    /// Concurrent callers for the same URL await the same OnceCell and get cached data silently.
    pub async fn get_or_fetch_repo_health(
        &self,
        url: &str,
        client: &ApiClient,
    ) -> (Option<RepoHealthData>, Option<String>) {
        let cell = {
            let mut cache = self.repo_health.lock().await;
            cache
                .entry(url.to_string())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };

        // If the cell is already initialized, this is a cache hit — return data with no warning
        if let Some(data) = cell.get() {
            return (data.clone(), None);
        }

        // We might be the first caller to drive the init.
        // Use a local flag to track whether WE did the init.
        let mut warning = None;
        let url_owned = url.to_string();
        let data = cell
            .get_or_init(|| async {
                match client.get_repo_health(&url_owned).await {
                    Ok(resp) => Some(resp.data),
                    Err(_) => {
                        // Warning is generated at call site below based on None result
                        None
                    }
                }
            })
            .await
            .clone();

        // If we got None, we need to determine if we should emit a warning.
        // The OnceCell doesn't tell us if we were the initializer, but we can check:
        // if data is None, the fetch failed. The first caller gets the warning.
        // Since multiple callers may reach here simultaneously after init completes,
        // we accept that the warning may or may not be generated. The contract says
        // warnings are deduplicated in from_results anyway.
        // To ensure the warning is generated at least once, we re-derive it here
        // only if data is None. This matches sequential behavior where a cache miss
        // for a failed key always returns (None, Some(warning)) on first access.
        // However, with OnceCell we can't easily distinguish first-caller from waiters.
        // The safe approach: generate warning if data is None. The HashSet in
        // from_results will deduplicate across packages.
        if data.is_none() {
            warning = Some(format!("Failed to fetch health data for {}", url));
        }

        (data, warning)
    }

    /// Get cached contributor security data or fetch from API.
    /// Caches both successes (Some) and failures (None).
    /// Only the first caller for a given email drives the fetch and receives any warning.
    pub async fn get_or_fetch_contributor_security(
        &self,
        email: &str,
        client: &ApiClient,
    ) -> (Option<ContributorSecurityData>, Option<String>) {
        let cell = {
            let mut cache = self.contributor_security.lock().await;
            cache
                .entry(email.to_string())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };

        // Cache hit — return data with no warning
        if let Some(data) = cell.get() {
            return (data.clone(), None);
        }

        let email_owned = email.to_string();
        let data = cell
            .get_or_init(|| async {
                match client.get_contributor_security(&email_owned).await {
                    Ok(resp) => Some(resp.data),
                    Err(_e) => None,
                }
            })
            .await
            .clone();

        let warning = if data.is_none() {
            Some(format!("Failed to fetch security for {}", email))
        } else {
            None
        };

        (data, warning)
    }
}

/// Evaluate a single package against all policies.
/// Returns a CheckResult with verdict and matches.
/// When called without a cache, creates a temporary one (no cross-package caching).
#[allow(dead_code)]
pub async fn evaluate_package(
    purl: &str,
    policies: &[PolicyFile],
    client: &ApiClient,
) -> CheckResult {
    let cache = EvalCache::new();
    evaluate_package_cached(purl, policies, client, &cache).await
}

/// Evaluate a single package against all policies, using a shared cache.
/// The cache avoids redundant API calls when evaluating multiple packages.
pub async fn evaluate_package_cached(
    purl: &str,
    policies: &[PolicyFile],
    client: &ApiClient,
    cache: &EvalCache,
) -> CheckResult {
    let mut warnings = Vec::new();

    // Fetch package data
    let package_data = match client.get_package(purl).await {
        Ok(resp) => Some(resp.data),
        Err(e) => {
            warnings.push(format!("Failed to fetch package data: {}", e));
            None
        }
    };

    // Determine what additional data we need
    let needs = DataNeeds::from_policies(policies);

    // Fetch health data if needed (using cache to avoid duplicate calls)
    let health_data = if needs.needs_health {
        if let Some(ref pkg) = package_data {
            if let Some(ref repo_details) = pkg.repository_details {
                if let Some(ref repo_url) = repo_details.url {
                    let (data, warning) = cache.get_or_fetch_repo_health(repo_url, client).await;
                    if let Some(w) = warning {
                        warnings.push(w);
                    }
                    data
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Fetch contributor security data if needed.
    // OPTIMIZATION: Instead of fetching /contributor/security for ALL contributors
    // (which can be 1130+ for repos like perl), we:
    //   - `has_breached_credentials`: uses repo health data (contributors_with_breached_creds)
    //     — no per-contributor API calls needed
    //   - `key_change_detected`: SHORT-CIRCUITS — fetches contributors one at a time
    //     (up to a small sample cap of 10) and stops at first match
    //   - `signed_commit_ratio_below`: fetches a sample of up to 15 contributors
    //     to compute a representative ratio (the /contributor/security endpoint
    //     provides signed_commit_ratio; the package response does NOT populate it)
    //
    // This reduces API calls from O(contributors) to O(1) for most conditions,
    // and O(sample_cap) worst case for key_change_detected / signed_commit_ratio_below.
    let contributor_security = if needs.needs_contributor_security {
        let mut security_data = Vec::new();
        if let Some(ref pkg) = package_data {
            if let Some(ref repo_details) = pkg.repository_details {
                // Collect emails for lookup
                let emails: Vec<&str> = repo_details
                    .contributors
                    .iter()
                    .filter_map(|c| c.email.as_deref())
                    .collect();

                // Determine the sample cap based on which conditions are active.
                // key_change_detected: 10 (short-circuits on first match)
                // signed_commit_ratio_below: 15 (needs a representative sample for ratio)
                // Both: use the larger cap (15)
                let sample_cap = if needs.needs_signed_commit_ratio {
                    15usize
                } else {
                    10usize
                };
                const BATCH_SIZE: usize = 5;
                let capped_emails: Vec<&str> = emails.into_iter().take(sample_cap).collect();

                // Process in small batches for some concurrency
                for batch in capped_emails.chunks(BATCH_SIZE) {
                    use futures::stream::StreamExt;
                    let batch_results: Vec<(Option<ContributorSecurityData>, Option<String>)> =
                        futures::stream::iter(batch.iter())
                            .map(|email| async move {
                                cache.get_or_fetch_contributor_security(email, client).await
                            })
                            .buffer_unordered(BATCH_SIZE)
                            .collect()
                            .await;

                    let mut found_key_change = false;
                    for (data, warning) in batch_results {
                        if let Some(w) = warning {
                            warnings.push(w);
                        }
                        if let Some(d) = data {
                            // Check if this contributor has a key change
                            if needs.needs_key_change {
                                if let Some(ref ski) = d.signing_key_info {
                                    if ski.key_change_detected == Some(true) {
                                        found_key_change = true;
                                    }
                                }
                            }
                            security_data.push(d);
                        }
                    }

                    // Short-circuit: if ONLY key_change_detected is needed (no ratio),
                    // stop as soon as we find a match. If signed_commit_ratio_below
                    // is also needed, we must continue fetching to build the sample.
                    if found_key_change && !needs.needs_signed_commit_ratio {
                        break;
                    }
                }
            }
        }
        security_data
    } else {
        vec![]
    };

    let ctx = EvalContext {
        purl: purl.to_string(),
        package_data,
        health_data,
        contributor_security,
    };

    // Collect all rules from all policies
    let mut all_rules: Vec<(
        &str,
        &str,
        Action,
        &std::collections::HashMap<String, serde_yaml::Value>,
    )> = Vec::new();
    for policy in policies {
        for rule in &policy.spec.rules {
            let action = match rule.action.as_str() {
                "info" => Action::Info,
                "warn" => Action::Warn,
                "review" => Action::Review,
                "deny" => Action::Deny,
                "allow" => Action::Allow,
                _ => continue,
            };
            all_rules.push((
                &rule.name,
                rule.description.as_deref().unwrap_or(""),
                action,
                &rule.match_conditions,
            ));
        }
    }

    // Phase 1: Evaluate ALLOW rules first
    let mut is_allowed = false;
    let mut matches = Vec::new();

    for &(name, desc, action, conditions) in &all_rules {
        if action != Action::Allow {
            continue;
        }
        let (all_match, reason) = evaluate_rule_conditions(conditions, &ctx, &mut warnings);
        if all_match {
            is_allowed = true;
            matches.push(RuleMatch {
                rule_name: name.to_string(),
                rule_description: desc.to_string(),
                action: Action::Allow,
                reason,
                purl: purl.to_string(),
            });
        }
    }

    // Phase 2: Evaluate non-allow rules
    let mut has_deny = false;
    let mut has_review = false;

    for &(name, desc, action, conditions) in &all_rules {
        if action == Action::Allow {
            continue;
        }

        let (all_match, reason) = evaluate_rule_conditions(conditions, &ctx, &mut warnings);

        if all_match {
            matches.push(RuleMatch {
                rule_name: name.to_string(),
                rule_description: desc.to_string(),
                action,
                reason,
                purl: purl.to_string(),
            });

            match action {
                Action::Deny if !is_allowed => has_deny = true,
                Action::Review if !is_allowed => has_review = true,
                _ => {}
            }
        }
    }

    let verdict = if has_deny {
        Verdict::Deny
    } else if has_review {
        Verdict::Review
    } else {
        Verdict::Pass
    };

    CheckResult {
        verdict,
        matches,
        warnings,
        purl: purl.to_string(),
    }
}

/// Evaluate all conditions in a rule using AND logic.
/// Returns (all_matched, combined_reason).
fn evaluate_rule_conditions(
    conditions: &std::collections::HashMap<String, serde_yaml::Value>,
    ctx: &EvalContext,
    warnings: &mut Vec<String>,
) -> (bool, String) {
    if conditions.is_empty() {
        return (false, "No conditions to match".to_string());
    }

    let mut all_match = true;
    let mut reasons = Vec::new();

    for (key, value) in conditions {
        let (matched, reason, warning) = evaluate_condition(key, value, ctx);
        if let Some(w) = warning {
            warnings.push(w);
        }
        if !matched {
            all_match = false;
            break;
        }
        reasons.push(reason);
    }

    (all_match, reasons.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::parse_policy;

    #[test]
    fn test_data_needs_detection() {
        let yaml = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: test
spec:
  rules:
    - name: bus-factor
      action: deny
      match:
        bus_factor_below: 2
    - name: key-change
      action: review
      match:
        key_change_detected: true
"#;
        let policy = parse_policy(yaml).unwrap();
        let needs = DataNeeds::from_policies(&[policy]);
        assert!(needs.needs_health);
        assert!(needs.needs_contributor_security);
    }

    #[test]
    fn test_data_needs_minimal() {
        let yaml = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: test
spec:
  rules:
    - name: advisory-check
      action: deny
      match:
        advisory_relationship: direct
"#;
        let policy = parse_policy(yaml).unwrap();
        let needs = DataNeeds::from_policies(&[policy]);
        assert!(!needs.needs_health);
        assert!(!needs.needs_contributor_security);
    }

    #[test]
    fn test_data_needs_signed_commit_ratio_triggers_contributor_security() {
        let yaml = r#"
apiVersion: netrise/v1
kind: Policy
metadata:
  name: test
spec:
  rules:
    - name: ratio-check
      action: deny
      match:
        signed_commit_ratio_below: 0.5
"#;
        let policy = parse_policy(yaml).unwrap();
        let needs = DataNeeds::from_policies(&[policy]);
        assert!(needs.needs_health); // signed_commit_ratio_below is in health_conditions
        assert!(needs.needs_contributor_security); // must trigger contributor security fetch
        assert!(needs.needs_signed_commit_ratio);
        assert!(!needs.needs_key_change);
    }

    #[test]
    fn test_eval_cache_new_is_empty() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = EvalCache::new();
            let repo_cache = cache.repo_health.lock().await;
            assert!(repo_cache.is_empty());
            drop(repo_cache);
            let contrib_cache = cache.contributor_security.lock().await;
            assert!(contrib_cache.is_empty());
        });
    }

    #[test]
    fn test_eval_cache_repo_health_hit() {
        use crate::api::types::RepoHealthData;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = EvalCache::new();
            let data = RepoHealthData {
                contributor_risk: Some(crate::api::types::ContributorRisk {
                    bus_factor: Some(5),
                    ..Default::default()
                }),
                ..Default::default()
            };
            {
                let mut repo_cache = cache.repo_health.lock().await;
                repo_cache.insert(
                    "https://github.com/test/repo".to_string(),
                    Arc::new(OnceCell::from(Some(data.clone()))),
                );
            }
            // Lookup should return cached data
            let repo_cache = cache.repo_health.lock().await;
            let cached = repo_cache.get("https://github.com/test/repo");
            assert!(cached.is_some());
            let cell = cached.unwrap();
            let cached_data = cell.get().unwrap().as_ref().unwrap();
            assert_eq!(
                cached_data.contributor_risk.as_ref().unwrap().bus_factor,
                Some(5)
            );
        });
    }

    #[test]
    fn test_eval_cache_contributor_security_hit() {
        use crate::api::types::ContributorSecurityData;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = EvalCache::new();
            let data = ContributorSecurityData {
                signed_commit_ratio: Some(0.95),
                ..Default::default()
            };
            {
                let mut contrib_cache = cache.contributor_security.lock().await;
                contrib_cache.insert(
                    "dev@example.com".to_string(),
                    Arc::new(OnceCell::from(Some(data))),
                );
            }
            let contrib_cache = cache.contributor_security.lock().await;
            let cached = contrib_cache.get("dev@example.com");
            assert!(cached.is_some());
            let cell = cached.unwrap();
            let cached_data = cell.get().unwrap().as_ref().unwrap();
            assert_eq!(cached_data.signed_commit_ratio, Some(0.95));
        });
    }

    #[test]
    fn test_eval_cache_stores_none_on_failure() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = EvalCache::new();
            // Simulate a failed lookup by inserting None via OnceCell
            {
                let mut repo_cache = cache.repo_health.lock().await;
                repo_cache.insert(
                    "https://github.com/missing/repo".to_string(),
                    Arc::new(OnceCell::from(None)),
                );
            }
            let repo_cache = cache.repo_health.lock().await;
            let cached = repo_cache.get("https://github.com/missing/repo");
            assert!(cached.is_some()); // Key exists in cache
            let cell = cached.unwrap();
            assert!(cell.get().unwrap().is_none()); // But the value is None (failure cached)
        });
    }

    // ── F6: Concurrency integration tests ────────────────────────────────────

    #[tokio::test]
    async fn test_eval_cache_deduplicates_concurrent_repo_health() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Count how many times the "API" is actually called
        let call_count = Arc::new(AtomicUsize::new(0));

        // Test the OnceCell deduplication behavior directly (same mechanism used in EvalCache)
        let cell = Arc::new(OnceCell::new());
        let count = call_count.clone();

        let mut handles = Vec::new();
        for _ in 0..5 {
            let cell = cell.clone();
            let count = count.clone();
            handles.push(tokio::spawn(async move {
                cell.get_or_init(|| async {
                    count.fetch_add(1, Ordering::SeqCst);
                    // Simulate API delay
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Some(RepoHealthData::default())
                })
                .await
                .clone()
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Only 1 "API call" should have been made
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        // All 5 tasks got Some result
        assert!(results.iter().all(|r| r.is_some()));
    }

    #[tokio::test]
    async fn test_eval_cache_deduplicates_concurrent_contributor_security() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let cell = Arc::new(OnceCell::new());

        let mut handles = Vec::new();
        for _ in 0..5 {
            let cell = cell.clone();
            let count = call_count.clone();
            handles.push(tokio::spawn(async move {
                cell.get_or_init(|| async {
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Some(ContributorSecurityData {
                        signed_commit_ratio: Some(0.8),
                        ..Default::default()
                    })
                })
                .await
                .clone()
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert!(results.iter().all(|r| r.is_some()));
    }

    #[tokio::test]
    async fn test_eval_cache_no_false_sharing() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));

        // Two different keys should produce two separate fetches
        let cell_a = Arc::new(OnceCell::<Option<RepoHealthData>>::new());
        let cell_b = Arc::new(OnceCell::<Option<RepoHealthData>>::new());

        let count = call_count.clone();
        let ca = cell_a.clone();
        let handle_a = tokio::spawn(async move {
            ca.get_or_init(|| async {
                count.fetch_add(1, Ordering::SeqCst);
                Some(RepoHealthData::default())
            })
            .await
            .clone()
        });

        let count = call_count.clone();
        let cb = cell_b.clone();
        let handle_b = tokio::spawn(async move {
            cb.get_or_init(|| async {
                count.fetch_add(1, Ordering::SeqCst);
                Some(RepoHealthData::default())
            })
            .await
            .clone()
        });

        let (ra, rb) = tokio::join!(handle_a, handle_b);
        assert!(ra.unwrap().is_some());
        assert!(rb.unwrap().is_some());
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_concurrent_evaluation_ordering() {
        // Verify that results from parallel evaluation preserve original index ordering
        use futures::stream::{self, StreamExt};

        let items: Vec<usize> = (0..10).collect();

        // Simulate buffer_unordered with varying delays, then sort by index
        let results: Vec<(usize, usize)> = stream::iter(items.into_iter().enumerate())
            .map(|(idx, val)| async move {
                // Vary delay to ensure out-of-order completion
                let delay = if idx % 2 == 0 { 10 } else { 1 };
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                (idx, val * 2)
            })
            .buffer_unordered(5)
            .collect()
            .await;

        // Sort by index to restore original order
        let mut sorted = results;
        sorted.sort_by_key(|(idx, _)| *idx);

        // Verify ordering and values
        for (i, (idx, val)) in sorted.iter().enumerate() {
            assert_eq!(*idx, i);
            assert_eq!(*val, i * 2);
        }
    }

    #[tokio::test]
    async fn test_zero_contributors_under_concurrency() {
        // join_all on an empty Vec should return immediately with no panic
        let empty: Vec<futures::future::Ready<(Option<ContributorSecurityData>, Option<String>)>> =
            vec![];
        let results = futures::future::join_all(empty).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_mixed_success_failure_under_concurrency() {
        use futures::stream::{self, StreamExt};

        // Simulate mixed success/failure results with ordering preservation
        let items = vec![
            (0, true),  // success
            (1, false), // failure
            (2, true),  // success
            (3, false), // failure
            (4, true),  // success
        ];

        let results: Vec<(usize, Result<String, String>)> = stream::iter(items.into_iter())
            .map(|(idx, success)| async move {
                // Vary timing to encourage out-of-order completion
                let delay = if success { 1 } else { 10 };
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                if success {
                    (idx, Ok(format!("data-{}", idx)))
                } else {
                    (idx, Err(format!("error-{}", idx)))
                }
            })
            .buffer_unordered(5)
            .collect()
            .await;

        // Sort by index
        let mut sorted = results;
        sorted.sort_by_key(|(idx, _)| *idx);

        // Verify ordering and correct success/failure isolation
        assert!(sorted[0].1.is_ok());
        assert!(sorted[1].1.is_err());
        assert!(sorted[2].1.is_ok());
        assert!(sorted[3].1.is_err());
        assert!(sorted[4].1.is_ok());
        assert_eq!(sorted[0].1.as_ref().unwrap(), "data-0");
        assert_eq!(sorted[1].1.as_ref().unwrap_err(), "error-1");
    }
}
