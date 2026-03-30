use crate::api::ApiClient;
use crate::config::OutputFormat;
use crate::output::{HumanFormatter, JsonCheckOutput, SarifOutput};
use crate::policy::{self, AggregateCheckResult};
use crate::sbom;
use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &ApiClient,
    target: &str,
    policy_paths: &[String],
    policy_dir: Option<&str>,
    format: OutputFormat,
    no_color: bool,
    ascii: bool,
    verbose: u8,
    api_url: &str,
    quiet: bool,
) -> Result<i32> {
    // Load policies
    let policies =
        policy::load_policies(policy_paths, policy_dir).map_err(|e| anyhow::anyhow!("{}", e))?;

    if policies.is_empty() {
        bail!("No policy files provided. Use --policy <path> or --policy-dir <dir>");
    }

    // Check for empty rules (all policies combined)
    let total_rules: usize = policies.iter().map(|p| p.spec.rules.len()).sum();
    if total_rules == 0 {
        // Empty policy = pass with warning
        let result = AggregateCheckResult::from_results(vec![]);
        return output_results(&result, format, no_color, ascii, verbose, api_url, quiet);
    }

    // Determine if target is a file or PURL
    let purls = if std::path::Path::new(target).exists() {
        // It's a file — parse as SBOM
        let content = std::fs::read_to_string(target)
            .map_err(|e| anyhow::anyhow!("Failed to read file '{}': {}", target, e))?;

        let (components, warnings) = sbom::parse_sbom(&content, Some(target))
            .map_err(|e| anyhow::anyhow!("SBOM parse error: {}", e))?;

        for w in &warnings {
            eprintln!("[WARN] {}", w);
        }

        if components.is_empty() {
            eprintln!("[WARN] No packages found in SBOM file");
            let result = AggregateCheckResult::from_results(vec![]);
            return output_results(&result, format, no_color, ascii, verbose, api_url, quiet);
        }

        components.into_iter().map(|c| c.purl).collect::<Vec<_>>()
    } else {
        // It's a PURL
        if !target.starts_with("pkg:") {
            bail!(
                "Target '{}' is neither an existing file nor a valid PURL (must start with 'pkg:')",
                target
            );
        }
        vec![target.to_string()]
    };

    // Evaluate all packages concurrently (F4: cross-package parallelism)
    // buffer_unordered(20) allows up to 20 package evaluations in-flight.
    // The ApiClient semaphore (default 10) is the true HTTP-level throttle.
    let cache = policy::EvalCache::new();
    let mut indexed_results: Vec<(usize, policy::types::CheckResult)> =
        stream::iter(purls.iter().enumerate())
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
    indexed_results.sort_by_key(|(idx, _)| *idx);
    let check_results: Vec<_> = indexed_results.into_iter().map(|(_, r)| r).collect();

    let aggregate = AggregateCheckResult::from_results(check_results);
    output_results(&aggregate, format, no_color, ascii, verbose, api_url, quiet)
}

fn output_results(
    result: &AggregateCheckResult,
    format: OutputFormat,
    no_color: bool,
    ascii: bool,
    verbose: u8,
    api_url: &str,
    quiet: bool,
) -> Result<i32> {
    match format {
        OutputFormat::Json => {
            let json_out = JsonCheckOutput::from_aggregate(result, api_url);
            println!("{}", serde_json::to_string_pretty(&json_out)?);
        }
        OutputFormat::Sarif => {
            let sarif = SarifOutput::from_aggregate(result);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        OutputFormat::Human => {
            if quiet {
                // In quiet mode, only show the verdict line
                println!("Verdict: {}", result.overall_verdict);
            } else {
                let fmt = HumanFormatter::new(no_color, ascii, verbose);
                print!("{}", fmt.format_check_result(result));
            }
        }
    }

    Ok(result.overall_verdict.exit_code())
}
