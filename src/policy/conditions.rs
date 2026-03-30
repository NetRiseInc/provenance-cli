use crate::api::types::*;

/// Context needed for evaluating policy conditions against a single package.
pub struct EvalContext {
    pub purl: String,
    pub package_data: Option<PackageData>,
    pub health_data: Option<RepoHealthData>,
    pub contributor_security: Vec<ContributorSecurityData>,
}

/// Evaluate a single condition. Returns (matched, reason, warning).
/// If warning is Some, it means the condition couldn't be fully evaluated.
pub fn evaluate_condition(
    key: &str,
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    match key {
        "package_purl" => eval_package_purl(value, ctx),
        "advisory_relationship" => eval_advisory_relationship(value, ctx),
        "advisory_names" => eval_advisory_names(value, ctx),
        "has_breached_credentials" => eval_has_breached_credentials(value, ctx),
        "bus_factor_below" => eval_bus_factor_below(value, ctx),
        "signed_commit_ratio_below" => eval_signed_commit_ratio_below(value, ctx),
        "repo_archived" => eval_repo_archived(value, ctx),
        "repo_deprecated" => eval_repo_deprecated(value, ctx),
        "scorecard_score_below" => eval_scorecard_score_below(value, ctx),
        "no_recent_commits_days" => eval_no_recent_commits_days(value, ctx),
        "license_spdx" => eval_license_spdx(value, ctx),
        "key_change_detected" => eval_key_change_detected(value, ctx),
        "contributor_countries" => eval_contributor_countries(value, ctx),
        "contributor_emails" => eval_contributor_emails(value, ctx),
        "repo_urls" => eval_repo_urls(value, ctx),
        _ => (
            false,
            format!("Unknown condition: {}", key),
            Some(format!("Unknown condition: {}", key)),
        ),
    }
}

fn eval_package_purl(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let pattern = value.as_str().unwrap_or("");
    let matched = glob_match(pattern, &ctx.purl);
    (
        matched,
        format!("PURL '{}' matches pattern '{}'", ctx.purl, pattern),
        None,
    )
}

fn eval_advisory_relationship(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let target = value.as_str().unwrap_or("").to_lowercase();
    let pkg = match &ctx.package_data {
        Some(d) => d,
        None => {
            return (
                false,
                "No package data".to_string(),
                Some("Package data unavailable".to_string()),
            )
        }
    };

    let matched = pkg.advisories.iter().any(|a| {
        a.relationship
            .as_deref()
            .map(|r| r.to_lowercase() == target)
            .unwrap_or(false)
    });

    let reason = if matched {
        format!("Package has advisory with '{}' relationship", target)
    } else {
        format!("No '{}' advisory relationship found", target)
    };

    (matched, reason, None)
}

fn eval_advisory_names(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let patterns: Vec<String> = match value {
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_yaml::Value::String(s) => vec![s.clone()],
        _ => return (false, "Invalid advisory_names value".to_string(), None),
    };

    let pkg = match &ctx.package_data {
        Some(d) => d,
        None => {
            return (
                false,
                "No package data".to_string(),
                Some("Package data unavailable".to_string()),
            )
        }
    };

    for advisory in &pkg.advisories {
        for pattern in &patterns {
            if glob_match(pattern, &advisory.name) {
                return (
                    true,
                    format!("Advisory '{}' matches pattern '{}'", advisory.name, pattern),
                    None,
                );
            }
        }
    }

    (false, "No advisory name matches".to_string(), None)
}

fn eval_has_breached_credentials(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let expected = value.as_bool().unwrap_or(true);

    // Check repo health data for contributors_with_breached_creds
    if let Some(health) = &ctx.health_data {
        if let Some(risk) = &health.contributor_risk {
            if let Some(count) = risk.contributors_with_breached_creds {
                let has_breached = count > 0;
                if has_breached == expected {
                    return (
                        true,
                        format!("{} contributors with breached credentials", count),
                        None,
                    );
                } else {
                    return (
                        false,
                        format!("{} contributors with breached credentials", count),
                        None,
                    );
                }
            }
        }
    }

    // Fallback: check individual contributor security data
    if !ctx.contributor_security.is_empty() {
        let has_any = ctx
            .contributor_security
            .iter()
            .any(|cs| cs.has_breached_credentials.unwrap_or(false));
        if has_any == expected {
            return (
                true,
                "Contributor has breached credentials".to_string(),
                None,
            );
        } else {
            return (
                false,
                "No breached credentials found in contributor data".to_string(),
                None,
            );
        }
    }

    (
        false,
        "No credential breach data available".to_string(),
        Some("No breach data available; condition skipped".to_string()),
    )
}

fn eval_bus_factor_below(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let threshold = value_to_i64(value);

    if let Some(health) = &ctx.health_data {
        if let Some(risk) = &health.contributor_risk {
            if let Some(bf) = risk.bus_factor {
                let matched = bf < threshold;
                return (
                    matched,
                    format!("Bus factor is {} (threshold: {})", bf, threshold),
                    None,
                );
            }
        }
    }

    (
        false,
        "Health data unavailable".to_string(),
        Some("Health data unavailable; bus_factor_below skipped".to_string()),
    )
}

fn eval_signed_commit_ratio_below(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let threshold = value_to_f64(value);

    // Check contributor security data first (from /contributor/security API)
    for cs in &ctx.contributor_security {
        if let Some(ratio) = cs.signed_commit_ratio {
            if ratio < threshold {
                return (
                    true,
                    format!(
                        "Signed commit ratio {} is below threshold {}",
                        ratio, threshold
                    ),
                    None,
                );
            }
        }
    }

    // If we have contributor security data but no ratio is below threshold
    if !ctx.contributor_security.is_empty() {
        return (
            false,
            format!("All signed commit ratios are at or above {}", threshold),
            None,
        );
    }

    // Fallback: use per-contributor signed_commit_ratio from package response
    // (the /package endpoint includes this field on each contributor)
    if let Some(ref pkg) = ctx.package_data {
        if let Some(ref repo_details) = pkg.repository_details {
            let mut found_any = false;
            for contributor in &repo_details.contributors {
                if let Some(ratio) = contributor.signed_commit_ratio {
                    found_any = true;
                    if ratio < threshold {
                        return (
                            true,
                            format!(
                                "Contributor '{}' signed commit ratio {} is below threshold {}",
                                contributor.email.as_deref().unwrap_or("unknown"),
                                ratio,
                                threshold,
                            ),
                            None,
                        );
                    }
                }
            }
            if found_any {
                return (
                    false,
                    format!("All signed commit ratios are at or above {}", threshold),
                    None,
                );
            }
        }
    }

    (
        false,
        "No signed commit ratio data available".to_string(),
        Some("Signed commit ratio data unavailable; condition skipped".to_string()),
    )
}

fn eval_repo_archived(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let expected = value.as_bool().unwrap_or(true);

    if let Some(health) = &ctx.health_data {
        if let Some(activity) = &health.activity {
            if let Some(is_archived) = activity.is_archived {
                let matched = is_archived == expected;
                return (
                    matched,
                    format!("Repository archived: {}", is_archived),
                    None,
                );
            }
        }
    }

    (
        false,
        "Health data unavailable".to_string(),
        Some("Health data unavailable; repo_archived skipped".to_string()),
    )
}

fn eval_repo_deprecated(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let expected = value.as_bool().unwrap_or(true);

    if let Some(health) = &ctx.health_data {
        if let Some(activity) = &health.activity {
            if let Some(is_deprecated) = activity.is_deprecated {
                let matched = is_deprecated == expected;
                return (
                    matched,
                    format!("Repository deprecated: {}", is_deprecated),
                    None,
                );
            }
        }
    }

    (
        false,
        "Health data unavailable".to_string(),
        Some("Health data unavailable; repo_deprecated skipped".to_string()),
    )
}

fn eval_scorecard_score_below(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let threshold = value_to_f64(value);

    // Scorecard data may be in security_config
    if let Some(health) = &ctx.health_data {
        if let Some(sc) = &health.security_config {
            // Try to find a scorecard score in security_config
            if let Some(score) = sc.get("scorecard_score").and_then(|v| v.as_f64()) {
                let matched = score < threshold;
                return (
                    matched,
                    format!("Scorecard score {} (threshold: {})", score, threshold),
                    None,
                );
            }
            // Try nested scorecard object
            if let Some(scorecard) = sc.get("scorecard") {
                if let Some(score) = scorecard.get("score").and_then(|v| v.as_f64()) {
                    let matched = score < threshold;
                    return (
                        matched,
                        format!("Scorecard score {} (threshold: {})", score, threshold),
                        None,
                    );
                }
            }
        }
    }

    (
        false,
        "Scorecard data unavailable".to_string(),
        Some("Scorecard data unavailable; scorecard_score_below skipped".to_string()),
    )
}

fn eval_no_recent_commits_days(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let days = value_to_i64(value);

    if let Some(health) = &ctx.health_data {
        if let Some(activity) = &health.activity {
            if let Some(last_commit) = &activity.last_commit_date {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(last_commit) {
                    let now = chrono::Utc::now();
                    let elapsed = now.signed_duration_since(dt);
                    let elapsed_days = elapsed.num_days();
                    let matched = elapsed_days > days;
                    return (
                        matched,
                        format!(
                            "Last commit {} days ago (threshold: {} days)",
                            elapsed_days, days
                        ),
                        None,
                    );
                }
            }
        }
    }

    (
        false,
        "Commit date data unavailable".to_string(),
        Some("Commit date data unavailable; no_recent_commits_days skipped".to_string()),
    )
}

fn eval_license_spdx(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let flagged: Vec<String> = match value {
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_yaml::Value::String(s) => vec![s.clone()],
        _ => return (false, "Invalid license_spdx value".to_string(), None),
    };

    // Check health data for license
    if let Some(health) = &ctx.health_data {
        if let Some(hygiene) = &health.code_hygiene {
            if let Some(license) = &hygiene.license_spdx {
                let lic_upper = license.to_uppercase();
                for f in &flagged {
                    if f.to_uppercase() == "NONE"
                        && (lic_upper == "NOASSERTION" || lic_upper == "NONE" || license.is_empty())
                    {
                        return (
                            true,
                            format!("License is '{}' (flagged as NONE)", license),
                            None,
                        );
                    }
                    if lic_upper.contains(&f.to_uppercase()) {
                        return (
                            true,
                            format!("License '{}' matches flagged '{}'", license, f),
                            None,
                        );
                    }
                }
                return (
                    false,
                    format!("License '{}' not in flagged list", license),
                    None,
                );
            }
        }
    }

    // Fallback: check package_details.license
    if let Some(pkg) = &ctx.package_data {
        if let Some(details) = &pkg.package_details {
            if let Some(license) = &details.license {
                for f in &flagged {
                    if f.to_uppercase() == "NONE" && license.is_empty() {
                        return (true, "Package has no license".to_string(), None);
                    }
                    if license.to_uppercase().contains(&f.to_uppercase()) {
                        return (
                            true,
                            format!("License '{}' matches flagged '{}'", license, f),
                            None,
                        );
                    }
                }
                return (
                    false,
                    format!("License '{}' not in flagged list", license),
                    None,
                );
            }
        }
    }

    (
        false,
        "No license data available".to_string(),
        Some("License data unavailable; license_spdx skipped".to_string()),
    )
}

fn eval_key_change_detected(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let expected = value.as_bool().unwrap_or(true);

    for cs in &ctx.contributor_security {
        if let Some(ski) = &cs.signing_key_info {
            if let Some(kcd) = ski.key_change_detected {
                if kcd == expected {
                    return (true, format!("Signing key change detected: {}", kcd), None);
                }
            }
        }
    }

    if !ctx.contributor_security.is_empty() {
        return (false, "No key change detected".to_string(), None);
    }

    (
        false,
        "No contributor security data available".to_string(),
        Some("Contributor security data unavailable; key_change_detected skipped".to_string()),
    )
}

fn eval_contributor_countries(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let countries: Vec<String> = match value {
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_uppercase()))
            .collect(),
        serde_yaml::Value::String(s) => vec![s.to_uppercase()],
        _ => {
            return (
                false,
                "Invalid contributor_countries value".to_string(),
                None,
            )
        }
    };

    if let Some(health) = &ctx.health_data {
        if let Some(risk) = &health.contributor_risk {
            if let Some(geo) = &risk.maintainer_geo_distribution {
                for (country, count) in geo {
                    // The API returns full country names like "Finland", "China"
                    // We need to match both ISO codes and full names
                    let country_upper = country.to_uppercase();
                    for target in &countries {
                        if country_upper == *target || country_code_matches(&country_upper, target)
                        {
                            return (
                                true,
                                format!(
                                    "Contributors from {} ({} contributors) match country code {}",
                                    country, count, target
                                ),
                                None,
                            );
                        }
                    }
                }
                return (
                    false,
                    "No contributors from flagged countries".to_string(),
                    None,
                );
            }
        }
    }

    (
        false,
        "Geo distribution data unavailable".to_string(),
        Some("Geo distribution data unavailable; contributor_countries skipped".to_string()),
    )
}

fn eval_contributor_emails(
    value: &serde_yaml::Value,
    ctx: &EvalContext,
) -> (bool, String, Option<String>) {
    let patterns: Vec<String> = match value {
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_yaml::Value::String(s) => vec![s.clone()],
        _ => return (false, "Invalid contributor_emails value".to_string(), None),
    };

    let pkg = match &ctx.package_data {
        Some(d) => d,
        None => {
            return (
                false,
                "No package data".to_string(),
                Some("Package data unavailable; contributor_emails skipped".to_string()),
            )
        }
    };

    let repo_details = match &pkg.repository_details {
        Some(rd) => rd,
        None => {
            return (
                false,
                "No repository details".to_string(),
                Some("Repository details unavailable; contributor_emails skipped".to_string()),
            )
        }
    };

    for contributor in &repo_details.contributors {
        if let Some(email) = &contributor.email {
            for pattern in &patterns {
                if glob_match(pattern, email) {
                    return (
                        true,
                        format!(
                            "Contributor email '{}' matches pattern '{}'",
                            email, pattern
                        ),
                        None,
                    );
                }
            }
        }
    }

    (false, "No contributor email matches".to_string(), None)
}

fn eval_repo_urls(value: &serde_yaml::Value, ctx: &EvalContext) -> (bool, String, Option<String>) {
    let patterns: Vec<String> = match value {
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_yaml::Value::String(s) => vec![s.clone()],
        _ => return (false, "Invalid repo_urls value".to_string(), None),
    };

    let pkg = match &ctx.package_data {
        Some(d) => d,
        None => {
            return (
                false,
                "No package data".to_string(),
                Some("Package data unavailable; repo_urls skipped".to_string()),
            )
        }
    };

    let repo_details = match &pkg.repository_details {
        Some(rd) => rd,
        None => {
            return (
                false,
                "No repository details".to_string(),
                Some("Repository details unavailable; repo_urls skipped".to_string()),
            )
        }
    };

    let url = match &repo_details.url {
        Some(u) => u,
        None => {
            return (
                false,
                "No repository URL".to_string(),
                Some("Repository URL unavailable; repo_urls skipped".to_string()),
            )
        }
    };

    for pattern in &patterns {
        if glob_match(pattern, url) {
            return (
                true,
                format!("Repository URL '{}' matches pattern '{}'", url, pattern),
                None,
            );
        }
    }

    (false, "No repository URL matches".to_string(), None)
}

/// Match country code to country name or vice versa.
fn country_code_matches(name: &str, code: &str) -> bool {
    let mapping: &[(&str, &str)] = &[
        ("CHINA", "CN"),
        ("RUSSIA", "RU"),
        ("IRAN", "IR"),
        ("NORTH KOREA", "KP"),
        ("SYRIA", "SY"),
        ("CUBA", "CU"),
        ("FINLAND", "FI"),
        ("GERMANY", "DE"),
        ("UNITED STATES", "US"),
        ("UNITED KINGDOM", "GB"),
        ("FRANCE", "FR"),
        ("JAPAN", "JP"),
        ("SOUTH KOREA", "KR"),
        ("INDIA", "IN"),
        ("BRAZIL", "BR"),
        ("CANADA", "CA"),
        ("AUSTRALIA", "AU"),
        ("NETHERLANDS", "NL"),
        ("SWEDEN", "SE"),
        ("SWITZERLAND", "CH"),
        ("SPAIN", "ES"),
        ("ITALY", "IT"),
        ("POLAND", "PL"),
        ("UKRAINE", "UA"),
        ("TAIWAN", "TW"),
        ("ISRAEL", "IL"),
        ("NORWAY", "NO"),
        ("DENMARK", "DK"),
        ("PORTUGAL", "PT"),
        ("AUSTRIA", "AT"),
        ("BELGIUM", "BE"),
        ("CZECH REPUBLIC", "CZ"),
        ("ROMANIA", "RO"),
        ("HUNGARY", "HU"),
        ("IRELAND", "IE"),
        ("SINGAPORE", "SG"),
        ("NEW ZEALAND", "NZ"),
        ("MEXICO", "MX"),
        ("ARGENTINA", "AR"),
        ("COLOMBIA", "CO"),
        ("TURKEY", "TR"),
        ("SOUTH AFRICA", "ZA"),
        ("NIGERIA", "NG"),
        ("KENYA", "KE"),
        ("VIETNAM", "VN"),
        ("THAILAND", "TH"),
        ("MALAYSIA", "MY"),
        ("PHILIPPINES", "PH"),
        ("INDONESIA", "ID"),
        ("PAKISTAN", "PK"),
        ("BANGLADESH", "BD"),
        ("EGYPT", "EG"),
        ("SAUDI ARABIA", "SA"),
        ("UNITED ARAB EMIRATES", "AE"),
        ("QATAR", "QA"),
        ("GREECE", "GR"),
        ("BULGARIA", "BG"),
        ("CROATIA", "HR"),
        ("SERBIA", "RS"),
        ("SLOVAKIA", "SK"),
        ("SLOVENIA", "SI"),
        ("ESTONIA", "EE"),
        ("LATVIA", "LV"),
        ("LITHUANIA", "LT"),
    ];

    for &(full_name, iso_code) in mapping {
        if (name == full_name && code == iso_code) || (name == iso_code && code == full_name) {
            return true;
        }
    }
    false
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let glob_pattern = glob::Pattern::new(pattern);
    match glob_pattern {
        Ok(p) => p.matches(text),
        Err(_) => pattern == text,
    }
}

fn value_to_i64(value: &serde_yaml::Value) -> i64 {
    match value {
        serde_yaml::Value::Number(n) => n.as_i64().unwrap_or(0),
        _ => 0,
    }
}

fn value_to_f64(value: &serde_yaml::Value) -> f64 {
    match value {
        serde_yaml::Value::Number(n) => n.as_f64().unwrap_or(0.0),
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx_with_advisory(rel: &str) -> EvalContext {
        EvalContext {
            purl: "pkg:deb/debian/xz-utils@5.0.0-2".to_string(),
            package_data: Some(PackageData {
                advisories: vec![Advisory {
                    name: "NETR-2024-0001".to_string(),
                    relationship: Some(rel.to_string()),
                }],
                ..Default::default()
            }),
            health_data: None,
            contributor_security: vec![],
        }
    }

    #[test]
    fn test_advisory_relationship_direct() {
        let ctx = make_ctx_with_advisory("direct");
        let val = serde_yaml::Value::String("direct".to_string());
        let (matched, _, _) = eval_advisory_relationship(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_advisory_relationship_indirect() {
        let ctx = make_ctx_with_advisory("indirect");
        let val = serde_yaml::Value::String("indirect".to_string());
        let (matched, _, _) = eval_advisory_relationship(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_advisory_relationship_no_match() {
        let ctx = make_ctx_with_advisory("indirect");
        let val = serde_yaml::Value::String("direct".to_string());
        let (matched, _, _) = eval_advisory_relationship(&val, &ctx);
        assert!(!matched);
    }

    #[test]
    fn test_package_purl_glob() {
        let ctx = EvalContext {
            purl: "pkg:deb/debian/xz-utils@5.0.0-2".to_string(),
            package_data: None,
            health_data: None,
            contributor_security: vec![],
        };
        let val = serde_yaml::Value::String("pkg:deb/debian/xz-*".to_string());
        let (matched, _, _) = eval_package_purl(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_package_purl_no_match() {
        let ctx = EvalContext {
            purl: "pkg:npm/lodash@4.0.0".to_string(),
            package_data: None,
            health_data: None,
            contributor_security: vec![],
        };
        let val = serde_yaml::Value::String("pkg:deb/*".to_string());
        let (matched, _, _) = eval_package_purl(&val, &ctx);
        assert!(!matched);
    }

    #[test]
    fn test_bus_factor_below() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: Some(RepoHealthData {
                contributor_risk: Some(ContributorRisk {
                    bus_factor: Some(1),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            contributor_security: vec![],
        };
        let val = serde_yaml::from_str("2").unwrap();
        let (matched, _, _) = eval_bus_factor_below(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_bus_factor_not_below() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: Some(RepoHealthData {
                contributor_risk: Some(ContributorRisk {
                    bus_factor: Some(5),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            contributor_security: vec![],
        };
        let val = serde_yaml::from_str("2").unwrap();
        let (matched, _, _) = eval_bus_factor_below(&val, &ctx);
        assert!(!matched);
    }

    #[test]
    fn test_bus_factor_missing_data() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: None,
            contributor_security: vec![],
        };
        let val = serde_yaml::from_str("2").unwrap();
        let (matched, _, warning) = eval_bus_factor_below(&val, &ctx);
        assert!(!matched);
        assert!(warning.is_some());
    }

    #[test]
    fn test_repo_archived_false() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: Some(RepoHealthData {
                activity: Some(Activity {
                    is_archived: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            contributor_security: vec![],
        };
        let val = serde_yaml::Value::Bool(true);
        let (matched, _, _) = eval_repo_archived(&val, &ctx);
        assert!(!matched);
    }

    #[test]
    fn test_key_change_detected() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: None,
            contributor_security: vec![ContributorSecurityData {
                signing_key_info: Some(SigningKeyInfo {
                    key_change_detected: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let val = serde_yaml::Value::Bool(true);
        let (matched, _, _) = eval_key_change_detected(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_country_code_matching() {
        assert!(country_code_matches("CHINA", "CN"));
        assert!(country_code_matches("FINLAND", "FI"));
        assert!(!country_code_matches("CHINA", "FI"));
    }

    #[test]
    fn test_advisory_names_glob() {
        let ctx = make_ctx_with_advisory("direct");
        let val = serde_yaml::from_str("[\"NETR-*\"]").unwrap();
        let (matched, _, _) = eval_advisory_names(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_signed_commit_ratio_below() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: None,
            contributor_security: vec![ContributorSecurityData {
                signed_commit_ratio: Some(0.0),
                ..Default::default()
            }],
        };
        let val = serde_yaml::from_str("0.5").unwrap();
        let (matched, _, _) = eval_signed_commit_ratio_below(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_has_breached_credentials_from_health() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: Some(RepoHealthData {
                contributor_risk: Some(ContributorRisk {
                    contributors_with_breached_creds: Some(81),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            contributor_security: vec![],
        };
        let val = serde_yaml::Value::Bool(true);
        let (matched, _, _) = eval_has_breached_credentials(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_contributor_countries_match() {
        let mut geo = std::collections::HashMap::new();
        geo.insert("Finland".to_string(), 24);
        geo.insert("China".to_string(), 6);
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: Some(RepoHealthData {
                contributor_risk: Some(ContributorRisk {
                    maintainer_geo_distribution: Some(geo),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            contributor_security: vec![],
        };
        let val = serde_yaml::from_str("[CN]").unwrap();
        let (matched, _, _) = eval_contributor_countries(&val, &ctx);
        assert!(matched);
    }

    // ── contributor_emails tests ──────────────────────────────────────

    fn make_ctx_with_contributors(emails: Vec<Option<String>>) -> EvalContext {
        EvalContext {
            purl: "pkg:deb/debian/xz-utils@5.0.0-2".to_string(),
            package_data: Some(PackageData {
                repository_details: Some(RepositoryDetails {
                    contributors: emails
                        .into_iter()
                        .map(|e| Contributor {
                            email: e,
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            health_data: None,
            contributor_security: vec![],
        }
    }

    #[test]
    fn test_contributor_emails_exact_match() {
        let ctx = make_ctx_with_contributors(vec![Some("jiat0218@gmail.com".to_string())]);
        let val = serde_yaml::from_str("[\"jiat0218@gmail.com\"]").unwrap();
        let (matched, reason, _) = eval_contributor_emails(&val, &ctx);
        assert!(matched);
        assert!(reason.contains("jiat0218@gmail.com"));
    }

    #[test]
    fn test_contributor_emails_glob_match() {
        let ctx = make_ctx_with_contributors(vec![Some("jiat0218@gmail.com".to_string())]);
        let val = serde_yaml::from_str("[\"*@gmail.com\"]").unwrap();
        let (matched, _, _) = eval_contributor_emails(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_contributor_emails_no_match() {
        let ctx = make_ctx_with_contributors(vec![Some("jiat0218@gmail.com".to_string())]);
        let val = serde_yaml::from_str("[\"*@example.com\"]").unwrap();
        let (matched, _, _) = eval_contributor_emails(&val, &ctx);
        assert!(!matched);
    }

    #[test]
    fn test_contributor_emails_missing_package_data() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: None,
            contributor_security: vec![],
        };
        let val = serde_yaml::from_str("[\"*@gmail.com\"]").unwrap();
        let (matched, _, warning) = eval_contributor_emails(&val, &ctx);
        assert!(!matched);
        assert!(warning.is_some());
    }

    #[test]
    fn test_contributor_emails_single_string() {
        let ctx = make_ctx_with_contributors(vec![Some("jiat0218@gmail.com".to_string())]);
        let val = serde_yaml::Value::String("jiat0218@gmail.com".to_string());
        let (matched, _, _) = eval_contributor_emails(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_contributor_emails_multiple_patterns() {
        let ctx = make_ctx_with_contributors(vec![Some("jiat0218@gmail.com".to_string())]);
        let val = serde_yaml::from_str("[\"*@protonmail.com\", \"*0218*\"]").unwrap();
        let (matched, reason, _) = eval_contributor_emails(&val, &ctx);
        assert!(matched);
        assert!(reason.contains("*0218*"));
    }

    // ── repo_urls tests ─────────────────────────────────────────────────

    fn make_ctx_with_repo_url(url: Option<String>) -> EvalContext {
        EvalContext {
            purl: "pkg:deb/debian/xz-utils@5.0.0-2".to_string(),
            package_data: Some(PackageData {
                repository_details: Some(RepositoryDetails {
                    url,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            health_data: None,
            contributor_security: vec![],
        }
    }

    #[test]
    fn test_repo_urls_exact_match() {
        let ctx = make_ctx_with_repo_url(Some(
            "https://github.com/tukaani-project/xz.git".to_string(),
        ));
        let val = serde_yaml::from_str("[\"https://github.com/tukaani-project/xz.git\"]").unwrap();
        let (matched, _, _) = eval_repo_urls(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_repo_urls_glob_match() {
        let ctx = make_ctx_with_repo_url(Some(
            "https://github.com/tukaani-project/xz.git".to_string(),
        ));
        let val = serde_yaml::from_str("[\"*tukaani-project*\"]").unwrap();
        let (matched, _, _) = eval_repo_urls(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_repo_urls_github_org_glob() {
        let ctx = make_ctx_with_repo_url(Some(
            "https://github.com/tukaani-project/xz.git".to_string(),
        ));
        let val = serde_yaml::from_str("[\"*github.com/tukaani-project/*\"]").unwrap();
        let (matched, _, _) = eval_repo_urls(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_repo_urls_no_match() {
        let ctx = make_ctx_with_repo_url(Some(
            "https://github.com/tukaani-project/xz.git".to_string(),
        ));
        let val = serde_yaml::from_str("[\"*gitlab.com*\"]").unwrap();
        let (matched, _, _) = eval_repo_urls(&val, &ctx);
        assert!(!matched);
    }

    #[test]
    fn test_repo_urls_missing_package_data() {
        let ctx = EvalContext {
            purl: "pkg:test".to_string(),
            package_data: None,
            health_data: None,
            contributor_security: vec![],
        };
        let val = serde_yaml::from_str("[\"*github.com*\"]").unwrap();
        let (matched, _, warning) = eval_repo_urls(&val, &ctx);
        assert!(!matched);
        assert!(warning.is_some());
    }

    #[test]
    fn test_repo_urls_missing_url() {
        let ctx = make_ctx_with_repo_url(None);
        let val = serde_yaml::from_str("[\"*github.com*\"]").unwrap();
        let (matched, _, warning) = eval_repo_urls(&val, &ctx);
        assert!(!matched);
        assert!(warning.is_some());
    }

    #[test]
    fn test_repo_urls_single_string() {
        let ctx = make_ctx_with_repo_url(Some(
            "https://github.com/tukaani-project/xz.git".to_string(),
        ));
        let val = serde_yaml::Value::String("*tukaani-project*".to_string());
        let (matched, _, _) = eval_repo_urls(&val, &ctx);
        assert!(matched);
    }

    #[test]
    fn test_glob_match_wildcard() {
        assert!(glob_match("pkg:deb/*", "pkg:deb/debian/curl@7.0"));
        assert!(!glob_match("pkg:npm/*", "pkg:deb/debian/curl@7.0"));
        assert!(glob_match("NETR-*", "NETR-2024-0001"));
    }
}
