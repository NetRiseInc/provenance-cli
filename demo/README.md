# Provenance CLI Demo

This directory contains pre-packaged content for the demo workflow that scans real container images and evaluates them against supply chain policies.

## What the demo shows

1. **SBOM generation** -- Uses [syft](https://github.com/anchore/syft) to generate a CycloneDX SBOM from a container image
2. **Supply chain scanning** -- Runs `provenance scan` against the Provenance API to gather intelligence on every package
3. **Policy evaluation** -- Evaluates the SBOM against all example policies and a demo-specific policy
4. **SARIF integration** -- Generates SARIF output and uploads it to GitHub Code Scanning
5. **Actionable summary** -- Writes a markdown summary with finding counts and top violations

## Prerequisites

1. A `PROVENANCE_API_TOKEN` repository secret configured in GitHub
2. The demo workflow (`.github/workflows/demo.yml`) present in the repository

## How to trigger

**Option A: Push to the demo branch**

```bash
git checkout demo
git push origin demo
```

**Option B: Manual trigger (workflow_dispatch)**

Go to [Actions > Demo](../../actions/workflows/demo.yml) and click "Run workflow". You can customize:

- **image**: OCI image to scan (default: `debian:bookworm-slim`)
- **policy_dir**: Policy directory to evaluate (default: `examples/policies/`)

## Reading the results

### GitHub Actions summary

The workflow writes a markdown summary with:
- Total packages scanned
- Finding counts by action level (deny, review, warn, info, pass)
- Top 20 deny/review findings with package PURL and rule name
- List of policies evaluated

### Code Scanning tab

SARIF results are uploaded to GitHub Code Scanning. Navigate to **Security > Code scanning alerts** to see findings in GitHub's security view.

### Downloadable artifacts

The workflow uploads these artifacts:
- `sbom.cdx.json` -- The generated CycloneDX SBOM
- `results.json` -- Full JSON results from policy evaluation
- `results.sarif` -- SARIF file for import into other tools

## Files in this directory

| File | Description |
|------|-------------|
| `sample-sbom.cdx.json` | Pre-generated CycloneDX SBOM of `debian:bookworm-slim` |
| `policies/demo-policy.yaml` | Curated policy with warn/review/info actions (non-blocking) |
| `README.md` | This file |

## Customizing

### Different images

Trigger the workflow manually and specify a different image:
- `alpine:3.19` -- Minimal image, fewer packages
- `ubuntu:22.04` -- Ubuntu base, more packages
- `node:20-slim` -- Node.js runtime packages

### Different policies

Create new policy files in `demo/policies/` or point to any directory containing `.yaml` policy files. See the [policy engine documentation](../README.md#policy-engine) for the full conditions reference.
