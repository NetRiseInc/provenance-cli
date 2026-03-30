use crate::api::ApiClient;
use crate::config::OutputFormat;
use crate::output::{
    HumanFormatter, JsonAdvisory, JsonCheckOutput, JsonMetadata, JsonPackageSummary,
    JsonScanOutput, JsonScanWithPolicyOutput, SarifOutput,
};
use crate::policy;
use crate::sbom;
use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Read as _;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &ApiClient,
    file: Option<&str>,
    stdin: bool,
    health: bool,
    format: OutputFormat,
    no_color: bool,
    ascii: bool,
    verbose: u8,
    api_url: &str,
    _timeout: Option<u64>,
    policy_paths: &[String],
    policy_dir: Option<&str>,
    quiet: bool,
) -> Result<i32> {
    // Read SBOM content
    let (content, filename) = if stdin {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        (buf, "stdin".to_string())
    } else if let Some(path) = file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read SBOM file '{}': {}", path, e))?;
        (content, path.to_string())
    } else {
        bail!("Provide a file path or use --stdin");
    };

    if content.trim().is_empty() {
        match format {
            OutputFormat::Json => {
                let out = JsonScanOutput {
                    total_packages: 0,
                    scanned: 0,
                    failed: 0,
                    packages_with_advisories: 0,
                    packages: vec![],
                    errors: vec!["SBOM file is empty, no packages found".to_string()],
                    metadata: JsonMetadata {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        api_url: api_url.to_string(),
                    },
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            OutputFormat::Sarif => {
                let sarif = SarifOutput::empty();
                println!("{}", serde_json::to_string_pretty(&sarif)?);
            }
            OutputFormat::Human => {
                println!("SBOM file is empty. 0 packages found.");
            }
        }
        return Ok(0);
    }

    // Parse SBOM
    let (components, warnings) = match sbom::parse_sbom(&content, Some(&filename)) {
        Ok(r) => r,
        Err(e) => {
            match format {
                OutputFormat::Json => {
                    let out = JsonScanOutput {
                        total_packages: 0,
                        scanned: 0,
                        failed: 0,
                        packages_with_advisories: 0,
                        packages: vec![],
                        errors: vec![format!("Parse error: {}", e)],
                        metadata: JsonMetadata {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            version: env!("CARGO_PKG_VERSION").to_string(),
                            api_url: api_url.to_string(),
                        },
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
                OutputFormat::Sarif => {
                    let sarif = SarifOutput::empty();
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                }
                OutputFormat::Human => {
                    eprintln!("[ERROR] {}", e);
                    println!("0 packages found. Parse error.");
                }
            }
            return Ok(0);
        }
    };

    // Print warnings
    for w in &warnings {
        eprintln!("[WARN] {}", w);
    }

    if components.is_empty() {
        match format {
            OutputFormat::Json => {
                let out = JsonScanOutput {
                    total_packages: 0,
                    scanned: 0,
                    failed: 0,
                    packages_with_advisories: 0,
                    packages: vec![],
                    errors: warnings,
                    metadata: JsonMetadata {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        api_url: api_url.to_string(),
                    },
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            OutputFormat::Sarif => {
                let sarif = SarifOutput::empty();
                println!("{}", serde_json::to_string_pretty(&sarif)?);
            }
            OutputFormat::Human => {
                println!("No packages found in SBOM. 0 packages scanned.");
            }
        }
        return Ok(0);
    }

    let total = components.len();

    // Set up progress bar (only for human output on TTY)
    let show_progress =
        format == OutputFormat::Human && !no_color && atty::is(atty::Stream::Stderr);
    let pb = if show_progress {
        let bar = ProgressBar::new(total as u64);
        bar.set_style(
            ProgressStyle::with_template("[{bar:40.cyan/blue}] {pos}/{len} packages queried")
                .unwrap()
                .progress_chars("=>-"),
        );
        Some(bar)
    } else {
        None
    };

    // Query all packages concurrently (F5.1: parallel get_package)
    // buffer_unordered(20) with semaphore-bounded API client
    let pb_ref = &pb;
    let mut indexed_pkg_results: Vec<(usize, Result<(String, _), String>)> =
        stream::iter(components.iter().enumerate())
            .map(|(idx, comp)| {
                let purl = comp.purl.clone();
                async move {
                    let result = match client.get_package(&purl).await {
                        Ok(resp) => Ok((purl, resp)),
                        Err(e) => Err(format!("{}: {}", purl, e)),
                    };
                    if let Some(ref bar) = pb_ref {
                        bar.inc(1);
                    }
                    (idx, result)
                }
            })
            .buffer_unordered(20)
            .collect()
            .await;

    if let Some(bar) = pb {
        bar.finish_and_clear();
    }

    // Sort by original index for deterministic output
    indexed_pkg_results.sort_by_key(|(idx, _)| *idx);

    let mut results = Vec::new();
    let mut errors = Vec::new();
    for (_, result) in indexed_pkg_results {
        match result {
            Ok(pair) => results.push(pair),
            Err(e) => errors.push(e),
        }
    }

    let succeeded = results.len();
    let failed = errors.len();
    let advisories_count = results
        .iter()
        .filter(|(_, r)| !r.data.advisories.is_empty())
        .count();

    // Optional health fetch
    if health {
        // Collect unique repo URLs
        let repo_urls: std::collections::HashSet<String> = results
            .iter()
            .filter_map(|(_, r)| {
                r.data
                    .repository_details
                    .as_ref()
                    .and_then(|rd| rd.url.clone())
            })
            .collect();

        // F5.2: Parallel health data fetch
        // Collect into sorted Vec for deterministic verbose output
        let mut sorted_urls: Vec<&String> = repo_urls.iter().collect();
        sorted_urls.sort();

        let health_results: Vec<_> = stream::iter(sorted_urls.into_iter())
            .map(|url| async move {
                let result = client.get_repo_health(url).await;
                (url.clone(), result)
            })
            .buffer_unordered(20)
            .collect()
            .await;

        // Sort by URL for deterministic verbose output order
        let mut sorted_health = health_results;
        sorted_health.sort_by(|(a, _), (b, _)| a.cmp(b));

        for (url, result) in sorted_health {
            match result {
                Ok(health_resp) => {
                    if verbose > 0 {
                        let fmt = HumanFormatter::new(no_color, ascii, verbose);
                        eprint!("{}", fmt.format_health(&health_resp));
                    }
                }
                Err(e) => {
                    eprintln!("[WARN] Failed to fetch health for {}: {}", url, e);
                }
            }
        }
    }

    // Check if policies are provided — run policy evaluation before output
    let policies =
        policy::load_policies(policy_paths, policy_dir).map_err(|e| anyhow::anyhow!("{}", e))?;

    let policy_aggregate = if !policies.is_empty() {
        let purls: Vec<String> = results.iter().map(|(purl, _)| purl.clone()).collect();
        let cache = policy::EvalCache::new();

        // F5.3: Parallel policy evaluation across packages
        let mut indexed_check_results: Vec<(usize, _)> = stream::iter(purls.iter().enumerate())
            .map(|(idx, purl)| {
                let cache_ref = &cache;
                let policies_ref = &policies;
                async move {
                    let result =
                        policy::evaluate_package_cached(purl, policies_ref, client, cache_ref)
                            .await;
                    (idx, result)
                }
            })
            .buffer_unordered(20)
            .collect()
            .await;

        // Sort by original index for deterministic output
        indexed_check_results.sort_by_key(|(idx, _)| *idx);
        let check_results: Vec<_> = indexed_check_results.into_iter().map(|(_, r)| r).collect();

        Some(policy::AggregateCheckResult::from_results(check_results))
    } else {
        None
    };

    match format {
        OutputFormat::Json => {
            let packages: Vec<JsonPackageSummary> = results
                .iter()
                .map(|(purl, resp)| JsonPackageSummary {
                    purl: purl.clone(),
                    advisories: resp
                        .data
                        .advisories
                        .iter()
                        .map(|a| JsonAdvisory {
                            name: a.name.clone(),
                            relationship: a.relationship.clone(),
                        })
                        .collect(),
                    repo_url: resp
                        .data
                        .repository_details
                        .as_ref()
                        .and_then(|rd| rd.url.clone()),
                })
                .collect();

            let scan_out = JsonScanOutput {
                total_packages: total,
                scanned: succeeded,
                failed,
                packages_with_advisories: advisories_count,
                packages,
                errors,
                metadata: JsonMetadata {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    api_url: api_url.to_string(),
                },
            };

            if let Some(ref aggregate) = policy_aggregate {
                let combined = JsonScanWithPolicyOutput {
                    scan: scan_out,
                    policy: JsonCheckOutput::from_aggregate(aggregate, api_url),
                };
                println!("{}", serde_json::to_string_pretty(&combined)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&scan_out)?);
            }
        }
        OutputFormat::Sarif => {
            if let Some(ref aggregate) = policy_aggregate {
                let sarif = SarifOutput::from_aggregate(aggregate);
                println!("{}", serde_json::to_string_pretty(&sarif)?);
            } else {
                let sarif = SarifOutput::from_scan_results(&results);
                println!("{}", serde_json::to_string_pretty(&sarif)?);
            }
        }
        OutputFormat::Human => {
            if quiet {
                let summary = format!(
                    "{} packages, {} scanned, {} failed, {} with advisories",
                    total, succeeded, failed, advisories_count
                );
                if let Some(ref aggregate) = policy_aggregate {
                    println!("{}\nVerdict: {}", summary, aggregate.overall_verdict);
                } else {
                    println!("{}", summary);
                }
            } else {
                let fmt = HumanFormatter::new(no_color, ascii, verbose);
                print!(
                    "{}",
                    fmt.format_scan_summary(total, succeeded, failed, advisories_count)
                );

                // Show packages with advisories
                if advisories_count > 0 {
                    println!("\nPackages with advisories:");
                    for (purl, resp) in &results {
                        if !resp.data.advisories.is_empty() {
                            println!("  {} ({} advisories)", purl, resp.data.advisories.len());
                            for adv in &resp.data.advisories {
                                println!(
                                    "    - {} ({})",
                                    adv.name,
                                    adv.relationship.as_deref().unwrap_or("unknown")
                                );
                            }
                        }
                    }
                }

                // Show errors
                if !errors.is_empty() {
                    eprintln!("\nErrors:");
                    for e in &errors {
                        eprintln!("  {}", e);
                    }
                }

                // Show policy results
                if let Some(ref aggregate) = policy_aggregate {
                    print!("{}", fmt.format_check_result(aggregate));
                }
            }
        }
    }

    // Return the policy verdict exit code if policies were evaluated,
    // otherwise return 0 (no policy = success).
    let exit_code = policy_aggregate
        .as_ref()
        .map(|agg| agg.overall_verdict.exit_code())
        .unwrap_or(0);

    Ok(exit_code)
}

mod atty {
    pub enum Stream {
        Stderr,
    }

    pub fn is(_stream: Stream) -> bool {
        use std::io::IsTerminal;
        std::io::stderr().is_terminal()
    }
}
