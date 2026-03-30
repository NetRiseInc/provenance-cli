mod api;
mod commands;
mod config;
mod oci;
mod output;
mod policy;
mod sbom;
mod source;

use clap::{Parser, Subcommand};
use config::build_config;
use std::process;

/// provenance - Software supply chain intelligence from the command line
///
/// Query the Provenance API to assess software supply chain risk.
/// Supports single-package queries, bulk SBOM scanning, OCI container analysis,
/// and a YAML-based policy engine for CI/CD enforcement.
///
/// Getting started:
///   1. Set your API token: export PROVENANCE_API_TOKEN=<your-token>
///   2. Query a package: provenance query package 'pkg:deb/debian/curl@7.68.0'
///   3. Scan an SBOM: provenance scan sbom my-sbom.json
///   4. Check policy: provenance check my-sbom.json --policy policy.yaml
#[derive(Parser)]
#[command(
    name = "provenance",
    version = version_string(),
    about = "Software supply chain intelligence from the command line",
    long_about = None,
)]
struct Cli {
    /// API authentication token (overrides PROVENANCE_API_TOKEN env var)
    #[arg(long, global = true, env = "")]
    token: Option<String>,

    /// API base URL
    #[arg(long, global = true)]
    api_url: Option<String>,

    /// Output format: human, json, sarif
    #[arg(long, global = true, default_value = "human")]
    format: String,

    /// Increase verbosity (-v for verbose, -vv for debug)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Quiet mode — minimal output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Use ASCII-only table borders (no Unicode box drawing)
    #[arg(long, global = true)]
    ascii: bool,

    /// Maximum concurrent API requests
    #[arg(long, global = true)]
    concurrency: Option<usize>,

    /// API request timeout in seconds
    #[arg(long, global = true)]
    timeout: Option<u64>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Query the provenance API for packages, repos, contributors, or advisories
    Query {
        #[command(subcommand)]
        command: QueryCommands,
    },
    /// Scan SBOMs or OCI images for supply chain intelligence
    Scan {
        #[command(subcommand)]
        command: ScanCommands,
    },
    /// Evaluate packages or SBOMs against policy rules
    ///
    /// Exit codes:
    ///   0 - PASS: all checks passed (or only warn/info findings)
    ///   1 - DENY: at least one deny finding
    ///   2 - REVIEW: no deny findings, but at least one review finding
    ///   3 - ERROR: runtime error (network, auth, parse, etc.)
    Check {
        /// PURL or SBOM file path to evaluate
        target: String,
        /// Path to policy YAML file (can be specified multiple times)
        #[arg(long = "policy", action = clap::ArgAction::Append)]
        policies: Vec<String>,
        /// Directory containing policy YAML files (.yaml/.yml)
        #[arg(long = "policy-dir")]
        policy_dir: Option<String>,
    },
    /// Show or test configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum QueryCommands {
    /// Query package provenance by PURL
    ///
    /// Examples:
    ///   provenance query package 'pkg:deb/debian/curl@7.68.0'
    ///   provenance query package 'pkg:npm/lodash@4.17.21' --health
    ///   provenance query package 'pkg:deb/debian/xz-utils@5.0.0-2' --search
    Package {
        /// Package URL (PURL) to query
        purl: String,
        /// Also fetch repository health metrics
        #[arg(long)]
        health: bool,
        /// Search for similar packages instead of exact lookup
        #[arg(long)]
        search: bool,
        /// Find packages that depend on this package
        #[arg(long)]
        dependents: bool,
    },
    /// Query repository information
    ///
    /// Examples:
    ///   provenance query repo 'https://github.com/curl/curl.git'
    ///   provenance query repo 'https://github.com/tukaani-project/xz.git' --health
    Repo {
        /// Repository URL to query
        url: String,
        /// Also fetch repository health metrics
        #[arg(long)]
        health: bool,
    },
    /// Query contributor information by email or username
    ///
    /// Examples:
    ///   provenance query contributor 'user@example.com'
    ///   provenance query contributor 'user@example.com' --security
    Contributor {
        /// Email address or username (auto-detected: '@' means email)
        identifier: String,
        /// Also fetch security posture (breach status, signing keys)
        #[arg(long)]
        security: bool,
    },
    /// Query advisory details
    ///
    /// Examples:
    ///   provenance query advisory NETR-2024-0001
    Advisory {
        /// Advisory identifier (e.g., NETR-2024-0001)
        advisory_id: String,
    },
}

#[derive(Subcommand)]
enum ScanCommands {
    /// Scan an SBOM file for supply chain intelligence
    ///
    /// Supports CycloneDX JSON/XML, SPDX JSON/tag-value, and CSV formats.
    /// Auto-detects format from file content.
    ///
    /// Examples:
    ///   provenance scan sbom my-sbom.json
    ///   provenance scan sbom my-sbom.xml --format json
    ///   cat sbom.json | provenance scan sbom --stdin
    Sbom {
        /// Path to SBOM file
        file: Option<String>,
        /// Read SBOM from stdin
        #[arg(long)]
        stdin: bool,
        /// Also fetch repository health for each package
        #[arg(long)]
        health: bool,
        /// Per-request timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,
        /// Path to policy YAML file (can be specified multiple times)
        #[arg(long = "policy", action = clap::ArgAction::Append)]
        policies: Vec<String>,
        /// Directory containing policy YAML files (.yaml/.yml)
        #[arg(long = "policy-dir")]
        policy_dir: Option<String>,
    },
    /// Scan an OCI container image
    ///
    /// Extracts SBOM using cosign (preferred) or syft (fallback).
    /// Requires cosign or syft to be installed.
    ///
    /// Examples:
    ///   provenance scan oci alpine:latest
    ///   provenance scan oci myregistry.io/myimage:v1.0
    ///   provenance scan oci myregistry.io/myimage@sha256:abc123 --skip-verify
    Oci {
        /// OCI image reference (e.g., alpine:latest, registry/repo:tag)
        image: String,
        /// Skip cosign signature verification
        #[arg(long)]
        skip_verify: bool,
        /// Per-request timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show effective configuration (token redacted)
    Show,
    /// Test API connectivity and token validity
    Test,
}

fn version_string() -> &'static str {
    concat!(
        env!("CARGO_PKG_VERSION"),
        " (git: ",
        env!("PROVENANCE_GIT_HASH"),
        ", built: ",
        env!("PROVENANCE_BUILD_DATE"),
        ", rustc ",
        env!("PROVENANCE_RUSTC_VERSION"),
        ")"
    )
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let cfg = build_config(
        cli.token.as_deref(),
        cli.api_url.as_deref(),
        Some(&cli.format),
        cli.concurrency,
        cli.timeout,
        cli.verbose,
        cli.quiet,
        cli.no_color,
        cli.ascii,
    );

    let exit_code = match run(cli, &cfg).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {}", e);
            for cause in e.chain().skip(1) {
                eprintln!("  Caused by: {}", cause);
            }
            3
        }
    };

    process::exit(exit_code);
}

async fn run(cli: Cli, cfg: &config::AppConfig) -> anyhow::Result<i32> {
    match cli.command {
        Commands::Config { command } => {
            match command {
                ConfigCommands::Show => {
                    commands::config_cmd::show(cfg)?;
                }
                ConfigCommands::Test => {
                    commands::config_cmd::test(cfg).await?;
                }
            }
            Ok(0)
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "provenance", &mut std::io::stdout());
            Ok(0)
        }
        Commands::Query { command } => {
            let client = make_client(cfg)?;
            match command {
                QueryCommands::Package {
                    purl,
                    health,
                    search,
                    dependents,
                } => {
                    commands::query::package::run(
                        &client,
                        &purl,
                        health,
                        search,
                        dependents,
                        cfg.format,
                        cfg.no_color,
                        cfg.ascii,
                        cfg.verbose,
                        cfg.quiet,
                    )
                    .await?;
                }
                QueryCommands::Repo { url, health } => {
                    commands::query::repo::run(
                        &client,
                        &url,
                        health,
                        cfg.format,
                        cfg.no_color,
                        cfg.ascii,
                        cfg.verbose,
                        cfg.quiet,
                    )
                    .await?;
                }
                QueryCommands::Contributor {
                    identifier,
                    security,
                } => {
                    commands::query::contributor::run(
                        &client,
                        &identifier,
                        security,
                        cfg.format,
                        cfg.no_color,
                        cfg.ascii,
                        cfg.verbose,
                        cfg.quiet,
                    )
                    .await?;
                }
                QueryCommands::Advisory { advisory_id } => {
                    commands::query::advisory::run(
                        &client,
                        &advisory_id,
                        cfg.format,
                        cfg.no_color,
                        cfg.ascii,
                        cfg.verbose,
                        cfg.quiet,
                    )
                    .await?;
                }
            }
            Ok(0)
        }
        Commands::Scan { command } => {
            let client = make_client(cfg)?;
            match command {
                ScanCommands::Sbom {
                    file,
                    stdin,
                    health,
                    timeout,
                    policies,
                    policy_dir,
                } => {
                    let exit_code = commands::scan::sbom::run(
                        &client,
                        file.as_deref(),
                        stdin,
                        health,
                        cfg.format,
                        cfg.no_color,
                        cfg.ascii,
                        cfg.verbose,
                        &cfg.api_url,
                        timeout,
                        &policies,
                        policy_dir.as_deref(),
                        cfg.quiet,
                    )
                    .await?;
                    Ok(exit_code)
                }
                ScanCommands::Oci {
                    image,
                    skip_verify,
                    timeout,
                } => {
                    commands::scan::oci::run(
                        &client,
                        &image,
                        skip_verify,
                        cfg.format,
                        cfg.no_color,
                        cfg.ascii,
                        cfg.verbose,
                        &cfg.api_url,
                        timeout,
                        cfg.quiet,
                    )
                    .await?;
                    Ok(0)
                }
            }
        }
        Commands::Check {
            target,
            policies,
            policy_dir,
        } => {
            let client = make_client(cfg)?;
            let exit_code = commands::check::run(
                &client,
                &target,
                &policies,
                policy_dir.as_deref(),
                cfg.format,
                cfg.no_color,
                cfg.ascii,
                cfg.verbose,
                &cfg.api_url,
                cfg.quiet,
            )
            .await?;
            Ok(exit_code)
        }
    }
}

fn make_client(cfg: &config::AppConfig) -> anyhow::Result<api::ApiClient> {
    let token = cfg
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No API token configured.\n\n\
                 Set the PROVENANCE_API_TOKEN environment variable:\n\
                 \texport PROVENANCE_API_TOKEN=<your-token>\n\n\
                 Or use the --token flag:\n\
                 \tprovenance --token <your-token> query package ...\n\n\
                 Or add it to the config file (~/.config/provenance/config.yaml):\n\
                 \ttoken: <your-token>"
            )
        })?;

    Ok(api::ApiClient::new(
        &cfg.api_url,
        token,
        cfg.timeout,
        cfg.concurrency,
        cfg.verbose,
    )?)
}
