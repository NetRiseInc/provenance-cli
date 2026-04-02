# provenance

[![CI](https://github.com/NetRiseInc/provenance-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/NetRiseInc/provenance-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/NetRiseInc/provenance-cli)](https://github.com/NetRiseInc/provenance-cli/releases/latest)

Software supply chain intelligence from the command line.

provenance queries the [Provenance API](https://provenance.netrise.io) to surface risk in your software dependencies: who wrote it, where does it come from, has it been compromised, and does it meet your compliance policies. It works with individual packages, SBOMs, and container images, and integrates into CI/CD pipelines via YAML-based policy enforcement with semantic exit codes.

## What it does

- **Query** package provenance, repository health, contributor security posture, and advisory data
- **Scan** SBOMs (CycloneDX, SPDX, CSV) and OCI container images for supply chain risk indicators
- **Enforce** YAML-based policies that gate CI/CD on contributor risk, advisory exposure, repo health, and compliance requirements
- **Output** human-readable tables, structured JSON, or SARIF v2.1.0 for GitHub Code Scanning integration

## Installation

### From source

```bash
cargo install --path .

# Or build directly
cargo build --release
# Binary at ./target/release/provenance
```

Requires Rust 1.70+. For OCI container scanning, [syft](https://github.com/anchore/syft) or [cosign](https://github.com/sigstore/cosign) must be installed.

### Pre-built binaries

Download from the [Releases page](https://github.com/NetRiseInc/provenance-cli/releases/latest).

Available for: Linux (x86_64, aarch64), macOS (x86_64, aarch64/Apple Silicon).

```bash
# Linux x86_64 (statically linked, works on any distro)
curl -sL https://github.com/NetRiseInc/provenance-cli/releases/latest/download/provenance-linux-x86_64-musl.tar.gz | tar xz
sudo mv provenance /usr/local/bin/

# macOS Apple Silicon
curl -sL https://github.com/NetRiseInc/provenance-cli/releases/latest/download/provenance-darwin-aarch64.tar.gz | tar xz
sudo mv provenance /usr/local/bin/
```

> **Note:** The Linux binary is statically linked (musl) and has no runtime dependencies. A glibc-linked variant (`provenance-linux-x86_64-gnu`) is also available for environments that prefer dynamic linking.

## Quick start

```bash
# Configure authentication
export PROVENANCE_API_TOKEN=<your-token>

# Look up a package
provenance query package 'pkg:deb/debian/curl@7.68.0-1?arch=amd64&distro=debian-10'

# Scan a container image
provenance scan oci debian:bookworm-slim

# Generate an SBOM with syft, then evaluate it against policies
syft your-image:latest -o cyclonedx-json > sbom.json
provenance check sbom.json --policy examples/policies/

# CI one-liner: scan + enforce, exit non-zero on violations
provenance scan sbom sbom.json --policy policies/ --quiet
```

## Commands

### `provenance query` -- Interrogate individual entities

Query the Provenance API for detailed intelligence on packages, repositories, contributors, or advisories.

```bash
# Package provenance (dependencies, repo mapping, advisories, contributors)
provenance query package 'pkg:deb/debian/xz-utils@5.0.0-2?arch=amd64&distro=debian-6'
provenance query package 'pkg:deb/debian/xz-utils@5.0.0-2?arch=amd64&distro=debian-6' --health

# Search for all known versions/architectures of a package
provenance query package 'pkg:deb/debian/xz-utils' --search

# Reverse dependency lookup
provenance query package 'pkg:deb/debian/xz-utils@5.0.0-2?arch=amd64&distro=debian-6' --dependents

# Repository intelligence
provenance query repo 'https://github.com/tukaani-project/xz.git'
provenance query repo 'https://github.com/tukaani-project/xz.git' --health

# Contributor lookup with security posture
provenance query contributor 'user@example.com'
provenance query contributor 'user@example.com' --security
provenance query contributor 'ghusername'  # auto-detects email vs username

# Advisory details (affected packages and repos)
provenance query advisory NETR-2024-0001
```

### `provenance scan` -- Bulk analysis of SBOMs and containers

Parse an SBOM or extract one from an OCI image, then query every package against the API concurrently.

```bash
# Scan SBOM files (format auto-detected from content)
provenance scan sbom my-sbom.cdx.json          # CycloneDX JSON
provenance scan sbom my-sbom.cdx.xml           # CycloneDX XML
provenance scan sbom my-sbom.spdx.json         # SPDX JSON
provenance scan sbom my-sbom.spdx              # SPDX tag-value
provenance scan sbom packages.csv              # CSV with purl column
cat sbom.json | provenance scan sbom --stdin   # Read from stdin

# Scan with inline policy enforcement
provenance scan sbom sbom.json --policy policy.yaml
provenance scan sbom sbom.json --policy policies/  # Directory of policies

# Scan OCI container images directly (uses syft/cosign)
provenance scan oci debian:bookworm-slim
provenance scan oci myregistry.io/app:v2.1@sha256:abc123
```

### `provenance check` -- Policy evaluation

Evaluate a single package or an SBOM against one or more YAML policy files. This is the primary CI/CD integration point.

```bash
# Check a single package
provenance check 'pkg:deb/debian/xz-utils@5.0.0-2?arch=amd64&distro=debian-6' \
  --policy examples/policies/supply-chain-compromise.yaml

# Check an SBOM against multiple policies
provenance check sbom.json --policy ofac.yaml --policy repo-health.yaml

# Check against a directory of policies
provenance check sbom.json --policy examples/policies/
```

### `provenance config` and `provenance completions`

```bash
provenance config show     # Display effective configuration (token redacted)
provenance config test     # Verify API connectivity and token validity

provenance completions bash > /etc/bash_completion.d/provenance
provenance completions zsh > ~/.zfunc/_provenance
provenance completions fish > ~/.config/fish/completions/provenance.fish
```

## Policy engine

Policies are YAML files that define rules for evaluating packages against supply chain risk criteria. Each rule matches on conditions from API data and triggers an action.

### Policy file structure

```yaml
apiVersion: netrise/v1
kind: Policy
metadata:
  name: my-policy
  description: What this policy enforces
spec:
  rules:
    - name: rule-name
      description: What this rule checks
      action: deny        # deny | review | warn | info | allow
      message: "Why this matters"
      match:
        bus_factor_below: 2
        repo_archived: true  # Multiple conditions are AND-joined
```

### Actions and exit codes

| Action   | Behavior | Exit Code |
|----------|----------|-----------|
| `deny`   | Hard failure -- blocks CI/CD pipelines | 1 |
| `review` | Flags for human review | 2 |
| `warn`   | Logs a warning, does not affect exit | 0 |
| `info`   | Informational finding | 0 |
| `allow`  | Exempts matching packages from deny/review/warn | 0 |

`allow` rules are evaluated first. If a package matches an `allow` rule, it is exempted from `deny`, `review`, and `warn` rules. Multiple policies are combined -- all rules from all files are evaluated together.

### Conditions reference

| Condition | Type | Matches when... |
|-----------|------|-----------------|
| `advisory_relationship` | `"direct"` or `"indirect"` | Package has an advisory with this relationship |
| `advisory_names` | `["NETR-*", "CVE-*"]` | Advisory name matches any glob pattern |
| `has_breached_credentials` | `true` | Any contributor has breached credentials |
| `bus_factor_below` | `2` | Repository bus factor is below threshold |
| `signed_commit_ratio_below` | `0.5` | Signed commit ratio is below threshold |
| `contributor_countries` | `["CU", "KP", "IR"]` | Any contributor is from a listed country |
| `repo_archived` | `true` | Repository is archived |
| `repo_deprecated` | `true` | Package/repo is deprecated |
| `scorecard_score_below` | `5.0` | OpenSSF Scorecard score is below threshold |
| `no_recent_commits_days` | `365` | No commits in the last N days |
| `license_spdx` | `["NOASSERTION", "NONE"]` | License matches any listed identifier |
| `key_change_detected` | `true` | Signing key change detected for any contributor |
| `contributor_emails` | `["*@gmail.com", "user@*"]` | Any contributor email matches a glob pattern |
| `repo_urls` | `["*github.com/org/*"]` | Repository URL matches any glob pattern |
| `package_purl` | `"pkg:deb/debian/xz-*"` | Package PURL matches glob (typically used with `allow`) |

When a rule specifies multiple conditions, all must match (AND logic). Policy conditions that require additional API data (repo health, contributor security) are fetched automatically as needed.

### Example policies

The `examples/policies/` directory includes ready-to-use policies:

| File | What it enforces |
|------|-----------------|
| `ofac-compliance.yaml` | Flags contributors from OFAC-sanctioned countries (CU, IR, KP, SY, RU) |
| `supply-chain-compromise.yaml` | Detects supply chain compromise indicators -- advisories, signing key changes |
| `repo-health.yaml` | Enforces repository health standards -- bus factor, staleness, scorecard scores |
| `contributor-risk.yaml` | Flags contributor risk -- breached credentials combined with key changes |
| `targeted-risk.yaml` | Blocks known-bad contributor emails and flags suspicious repository sources |
| `full-compliance.yaml` | Comprehensive policy combining rules from all four domains |

## Output formats

All commands support three output formats via `--format`:

| Format | Flag | Use case |
|--------|------|----------|
| `human` | `--format human` (default) | Interactive terminal use -- colored tables with Unicode borders |
| `json` | `--format json` | Automation, scripting, piping to `jq` |
| `sarif` | `--format sarif` | GitHub Code Scanning, Azure DevOps, SARIF-compatible tools |

Additional display options: `--quiet` (verdict/summary only), `--no-color`, `--ascii` (ASCII table borders), `-v`/`-vv` (verbose/debug).

## Configuration

Resolved in priority order: CLI flags > environment variables > config file > defaults.

### Environment variables

| Variable | Description |
|----------|-------------|
| `PROVENANCE_API_TOKEN` | API authentication token (required) |
| `PROVENANCE_API_URL` | API base URL (default: `https://provenance.netrise.io/v1/provenance`) |
| `NO_COLOR` | Disable colored output ([no-color.org](https://no-color.org)) |

> **Backward compatibility:** The legacy environment variables `NETRISE_API_TOKEN` and `NETRISE_API_URL` are still supported as fallbacks. If `PROVENANCE_API_TOKEN` is not set, the CLI checks `NETRISE_API_TOKEN`. Same for the URL variable. Prefer the `PROVENANCE_` prefix for new configurations.

### Config file

`~/.config/provenance/config.yaml`:

```yaml
token: <your-token>
api_url: https://provenance.netrise.io/v1/provenance
default_format: human
concurrency: 10
timeout: 30
```

### Global flags

| Flag | Description |
|------|-------------|
| `--token <TOKEN>` | API token (overrides env var) |
| `--api-url <URL>` | API base URL |
| `--format <FORMAT>` | Output format: `human`, `json`, `sarif` |
| `-v` / `-vv` | Verbose / debug output |
| `-q` / `--quiet` | Minimal output |
| `--no-color` | Disable colors |
| `--ascii` | ASCII-only table borders |
| `--concurrency <N>` | Max concurrent API requests (default: 10) |
| `--timeout <SECS>` | Per-request timeout in seconds (default: 30) |

## CI/CD integration

### GitHub Actions

```yaml
- name: Scan SBOM
  run: |
    provenance check sbom.json --policy policies/ --quiet
  env:
    PROVENANCE_API_TOKEN: ${{ secrets.PROVENANCE_API_TOKEN }}
```

### SARIF upload to GitHub Code Scanning

```yaml
- name: Generate SARIF
  run: provenance check sbom.json --policy policies/ --format sarif > results.sarif
  env:
    PROVENANCE_API_TOKEN: ${{ secrets.PROVENANCE_API_TOKEN }}
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Exit code handling

```bash
provenance check sbom.json --policy policies/ --quiet
case $? in
  0) echo "All checks passed" ;;
  1) echo "DENIED -- policy violation" && exit 1 ;;
  2) echo "Review required" ;;
  3) echo "Scan error" && exit 1 ;;
esac
```

## GitHub Action

Use the provenance CLI as a GitHub Action in your workflows:

```yaml
- name: Generate SBOM
  run: syft your-image:latest -o cyclonedx-json > sbom.cdx.json

- name: Provenance Supply Chain Check
  uses: NetRiseInc/provenance-cli@v0.1.0
  with:
    sbom: sbom.cdx.json
    policy: policies/
    api-token: ${{ secrets.PROVENANCE_API_TOKEN }}
```

### Action inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `sbom` | No | | Path to SBOM file |
| `package` | No | | Package URL (PURL) to check |
| `policy` | No | | Policy file or directory |
| `format` | No | `human` | Output format: human, json, sarif |
| `api-token` | Yes | | Provenance API token |
| `version` | No | `latest` | CLI version to download |
| `quiet` | No | `false` | Summary-only output |

### SARIF upload example

```yaml
- name: Provenance Check
  id: provenance
  uses: NetRiseInc/provenance-cli@v0.1.0
  with:
    sbom: sbom.cdx.json
    policy: policies/
    format: sarif
    api-token: ${{ secrets.PROVENANCE_API_TOKEN }}
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.provenance.outputs.sarif-file }}
```

## Demo

A live demo pipeline scans `debian:bookworm-slim` against all example policies.

Run it manually via [workflow_dispatch](https://github.com/NetRiseInc/provenance-cli/actions/workflows/demo.yml) or push to the `demo` branch.

Results appear in:
- **Actions summary** -- markdown report with finding counts and top violations
- **Code Scanning tab** -- SARIF findings imported into GitHub's security view
- **Artifacts** -- downloadable SBOM, JSON results, and SARIF file

See [`demo/README.md`](demo/README.md) for details.

## Supported SBOM formats

| Format | Extensions | Detection |
|--------|-----------|-----------|
| CycloneDX JSON | `.cdx.json`, `.json` | `bomFormat` field |
| CycloneDX XML | `.cdx.xml`, `.xml` | `<bom>` root element |
| SPDX JSON | `.spdx.json`, `.json` | `spdxVersion` field |
| SPDX Tag-Value | `.spdx`, `.spdx.tv` | `SPDXVersion:` line |
| CSV | `.csv` | Header row with `purl` or `type,namespace,name,version` |

Format is auto-detected from file content. Use `--stdin` to pipe SBOMs from other tools.

## License

Apache-2.0
