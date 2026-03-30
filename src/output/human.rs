use crate::api::types::*;
use crate::policy::types::*;
use colored::*;
use comfy_table::{presets, Cell, ContentArrangement, Table};

pub struct HumanFormatter {
    pub no_color: bool,
    pub ascii: bool,
    #[allow(dead_code)]
    pub verbose: u8,
}

impl HumanFormatter {
    pub fn new(no_color: bool, ascii: bool, verbose: u8) -> Self {
        if no_color {
            colored::control::set_override(false);
        }
        Self {
            no_color,
            ascii,
            verbose,
        }
    }

    fn make_table(&self) -> Table {
        let mut table = Table::new();
        if self.ascii {
            table.load_preset(presets::ASCII_FULL);
        } else {
            table.load_preset(presets::UTF8_FULL);
        }
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table
    }

    pub fn format_package(&self, resp: &PackageResponse) -> String {
        let mut output = String::new();
        let data = &resp.data;

        output.push_str(&format!("\n{}\n", "Package Information".bold().underline()));

        let mut table = self.make_table();
        table.set_header(vec!["Field", "Value"]);

        table.add_row(vec![Cell::new("PURL"), Cell::new(&resp.purl)]);
        if let Some(ref t) = data.package_type {
            table.add_row(vec![Cell::new("Type"), Cell::new(t)]);
        }
        if let Some(ref v) = data.vendor {
            table.add_row(vec![Cell::new("Vendor"), Cell::new(v)]);
        }
        if let Some(ref p) = data.product {
            table.add_row(vec![Cell::new("Product"), Cell::new(p)]);
        }
        if let Some(ref v) = data.version {
            table.add_row(vec![Cell::new("Version"), Cell::new(v)]);
        }
        if let Some(ref a) = data.arch {
            table.add_row(vec![Cell::new("Arch"), Cell::new(a)]);
        }
        if let Some(ref d) = data.distro {
            table.add_row(vec![Cell::new("Distro"), Cell::new(d)]);
        }

        output.push_str(&format!("{}\n", table));

        // Package details
        if let Some(ref details) = data.package_details {
            if details.homepage.is_some() || details.license.is_some() {
                output.push_str(&format!("\n{}\n", "Package Details".bold()));
                let mut t = self.make_table();
                t.set_header(vec!["Field", "Value"]);
                if let Some(ref h) = details.homepage {
                    t.add_row(vec![Cell::new("Homepage"), Cell::new(h)]);
                }
                if let Some(ref l) = details.license {
                    t.add_row(vec![Cell::new("License"), Cell::new(l)]);
                }
                output.push_str(&format!("{}\n", t));
            }
        }

        // Dependencies
        if !data.dependencies.is_empty() {
            output.push_str(&format!(
                "\n{} ({})\n",
                "Dependencies".bold(),
                data.dependencies.len()
            ));
            let mut t = self.make_table();
            t.set_header(vec!["PURL", "Depth"]);
            for dep in &data.dependencies {
                t.add_row(vec![
                    Cell::new(&dep.purl),
                    Cell::new(dep.depth.map(|d| d.to_string()).unwrap_or_default()),
                ]);
            }
            output.push_str(&format!("{}\n", t));
        }

        // Repository details
        if let Some(ref repo) = data.repository_details {
            output.push_str(&format!("\n{}\n", "Repository Details".bold()));
            let mut t = self.make_table();
            t.set_header(vec!["Field", "Value"]);
            if let Some(ref url) = repo.url {
                t.add_row(vec![Cell::new("URL"), Cell::new(url)]);
            }
            if let Some(conf) = repo.confidence {
                t.add_row(vec![
                    Cell::new("Confidence"),
                    Cell::new(format!("{}%", conf)),
                ]);
            }
            if !repo.methods.is_empty() {
                t.add_row(vec![
                    Cell::new("Methods"),
                    Cell::new(repo.methods.join(", ")),
                ]);
            }
            output.push_str(&format!("{}\n", t));

            // Contributors
            if !repo.contributors.is_empty() {
                output.push_str(&format!(
                    "\n{} ({})\n",
                    "Contributors".bold(),
                    repo.contributors.len()
                ));
                let mut ct = self.make_table();
                ct.set_header(vec!["Email", "Signed Commits", "Unsigned Commits"]);
                for c in &repo.contributors {
                    ct.add_row(vec![
                        Cell::new(c.email.as_deref().unwrap_or("-")),
                        Cell::new(
                            c.has_signed_commits
                                .map(|b| if b { "Yes" } else { "No" })
                                .unwrap_or("-"),
                        ),
                        Cell::new(
                            c.has_unsigned_commits
                                .map(|b| if b { "Yes" } else { "No" })
                                .unwrap_or("-"),
                        ),
                    ]);
                }
                output.push_str(&format!("{}\n", ct));
            }
        }

        // Advisories
        if !data.advisories.is_empty() {
            output.push_str(&format!(
                "\n{} ({})\n",
                "Advisories".bold(),
                data.advisories.len()
            ));
            let mut t = self.make_table();
            t.set_header(vec!["Name", "Relationship"]);
            for adv in &data.advisories {
                let rel = adv.relationship.as_deref().unwrap_or("unknown");
                let rel_display = match rel {
                    "direct" => {
                        if self.no_color {
                            "direct".to_string()
                        } else {
                            "direct".red().bold().to_string()
                        }
                    }
                    "indirect" => {
                        if self.no_color {
                            "indirect".to_string()
                        } else {
                            "indirect".yellow().to_string()
                        }
                    }
                    other => other.to_string(),
                };
                t.add_row(vec![Cell::new(&adv.name), Cell::new(rel_display)]);
            }
            output.push_str(&format!("{}\n", t));
        }

        output
    }

    pub fn format_package_search(&self, resp: &PackageSearchResponse) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\n{} ({})\n",
            "Search Results".bold(),
            resp.purls.len()
        ));
        if resp.purls.is_empty() {
            output.push_str("  No matching packages found.\n");
        } else {
            let mut t = self.make_table();
            t.set_header(vec!["PURL"]);
            for purl in &resp.purls {
                t.add_row(vec![Cell::new(purl)]);
            }
            output.push_str(&format!("{}\n", t));
        }
        output
    }

    pub fn format_package_dependents(&self, resp: &PackageDependentsResponse) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\n{} ({})\n",
            "Dependents".bold(),
            resp.purls.len()
        ));
        if resp.purls.is_empty() {
            output.push_str("  No dependents found.\n");
        } else {
            let mut t = self.make_table();
            t.set_header(vec!["PURL"]);
            for purl in &resp.purls {
                t.add_row(vec![Cell::new(purl)]);
            }
            output.push_str(&format!("{}\n", t));
        }
        output
    }

    pub fn format_health(&self, resp: &RepoHealthResponse) -> String {
        let mut output = String::new();
        output.push_str(&format!("\n{}\n", "Repository Health".bold().underline()));

        let data = &resp.data;

        // Activity
        if let Some(ref act) = data.activity {
            output.push_str(&format!("\n{}\n", "Activity".bold()));
            let mut t = self.make_table();
            t.set_header(vec!["Metric", "Value"]);

            if let Some(ref cf) = act.commit_frequency {
                if let Some(d) = cf.days_90 {
                    t.add_row(vec![Cell::new("Commits (90 days)"), Cell::new(d)]);
                }
                if let Some(d) = cf.days_180 {
                    t.add_row(vec![Cell::new("Commits (180 days)"), Cell::new(d)]);
                }
                if let Some(d) = cf.days_365 {
                    t.add_row(vec![Cell::new("Commits (365 days)"), Cell::new(d)]);
                }
            }
            if let Some(v) = act.is_archived {
                t.add_row(vec![Cell::new("Archived"), Cell::new(v)]);
            }
            if let Some(v) = act.is_deprecated {
                t.add_row(vec![Cell::new("Deprecated"), Cell::new(v)]);
            }
            if let Some(ref v) = act.last_commit_date {
                t.add_row(vec![Cell::new("Last Commit"), Cell::new(v)]);
            }
            if let Some(v) = act.issue_close_rate_180d {
                t.add_row(vec![
                    Cell::new("Issue Close Rate (180d)"),
                    Cell::new(format!("{:.0}%", v * 100.0)),
                ]);
            }
            if let Some(v) = act.open_issues_count {
                t.add_row(vec![Cell::new("Open Issues"), Cell::new(v)]);
            }
            if let Some(v) = act.open_pr_count {
                t.add_row(vec![Cell::new("Open PRs"), Cell::new(v)]);
            }
            output.push_str(&format!("{}\n", t));
        }

        // Code Hygiene
        if let Some(ref hyg) = data.code_hygiene {
            output.push_str(&format!("\n{}\n", "Code Hygiene".bold()));
            let mut t = self.make_table();
            t.set_header(vec!["Metric", "Value"]);
            if let Some(ref v) = hyg.default_branch {
                t.add_row(vec![Cell::new("Default Branch"), Cell::new(v)]);
            }
            if let Some(ref v) = hyg.license_spdx {
                t.add_row(vec![Cell::new("License (SPDX)"), Cell::new(v)]);
            }
            if let Some(v) = hyg.is_fork {
                t.add_row(vec![Cell::new("Is Fork"), Cell::new(v)]);
            }
            if !hyg.topics.is_empty() {
                t.add_row(vec![Cell::new("Topics"), Cell::new(hyg.topics.join(", "))]);
            }
            if let Some(v) = hyg.repo_size_kb {
                t.add_row(vec![Cell::new("Repo Size (KB)"), Cell::new(v)]);
            }
            output.push_str(&format!("{}\n", t));
        }

        // Contributor Risk
        if let Some(ref risk) = data.contributor_risk {
            output.push_str(&format!("\n{}\n", "Contributor Risk".bold()));
            let mut t = self.make_table();
            t.set_header(vec!["Metric", "Value"]);
            if let Some(v) = risk.bus_factor {
                let display = if v <= 1 && !self.no_color {
                    format!("{}", v.to_string().red().bold())
                } else {
                    v.to_string()
                };
                t.add_row(vec![Cell::new("bus_factor"), Cell::new(display)]);
            }
            if let Some(v) = risk.active_contributors_12mo {
                t.add_row(vec![Cell::new("Active Contributors (12mo)"), Cell::new(v)]);
            }
            if let Some(v) = risk.contributors_with_breached_creds {
                let display = if v > 0 && !self.no_color {
                    format!("{}", v.to_string().red().bold())
                } else {
                    v.to_string()
                };
                t.add_row(vec![Cell::new("Breached Credentials"), Cell::new(display)]);
            }
            if let Some(ref geo) = risk.maintainer_geo_distribution {
                let geo_str: Vec<String> =
                    geo.iter().map(|(k, v)| format!("{}: {}", k, v)).collect();
                t.add_row(vec![
                    Cell::new("Geo Distribution"),
                    Cell::new(geo_str.join(", ")),
                ]);
            }
            output.push_str(&format!("{}\n", t));
        }

        // Security Config (raw)
        if let Some(ref sc) = data.security_config {
            output.push_str(&format!("\n{}\n", "Security Config".bold()));
            if let Some(obj) = sc.as_object() {
                let mut t = self.make_table();
                t.set_header(vec!["Key", "Value"]);
                for (k, v) in obj {
                    let val_str = match v {
                        serde_json::Value::Bool(b) => b.to_string(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::String(s) => s.clone(),
                        _ => serde_json::to_string_pretty(v).unwrap_or_default(),
                    };
                    t.add_row(vec![Cell::new(k), Cell::new(val_str)]);
                }
                output.push_str(&format!("{}\n", t));
            }
        }

        output
    }

    pub fn format_repo(&self, resp: &RepoResponse) -> String {
        let mut output = String::new();
        let data = &resp.data;

        output.push_str(&format!(
            "\n{}\n",
            "Repository Information".bold().underline()
        ));
        output.push_str(&format!("  URL: {}\n", resp.repo.bright_blue()));

        // Packages
        if !data.packages.is_empty() {
            output.push_str(&format!(
                "\n{} ({})\n",
                "Packages".bold(),
                data.packages.len()
            ));
            let mut t = self.make_table();
            t.set_header(vec!["PURL", "Confidence", "Methods"]);
            for pkg in &data.packages {
                t.add_row(vec![
                    Cell::new(pkg.purl.as_deref().unwrap_or("-")),
                    Cell::new(
                        pkg.confidence
                            .map(|c| format!("{}%", c))
                            .unwrap_or_default(),
                    ),
                    Cell::new(pkg.methods.join(", ")),
                ]);
            }
            output.push_str(&format!("{}\n", t));
        }

        // Contributors
        if !data.contributors.is_empty() {
            output.push_str(&format!(
                "\n{} ({})\n",
                "Contributors".bold(),
                data.contributors.len()
            ));
            let mut t = self.make_table();
            t.set_header(vec!["Email", "Signed Commits", "Unsigned Commits"]);
            for c in &data.contributors {
                t.add_row(vec![
                    Cell::new(c.email.as_deref().unwrap_or("-")),
                    Cell::new(
                        c.has_signed_commits
                            .map(|b| if b { "Yes" } else { "No" })
                            .unwrap_or("-"),
                    ),
                    Cell::new(
                        c.has_unsigned_commits
                            .map(|b| if b { "Yes" } else { "No" })
                            .unwrap_or("-"),
                    ),
                ]);
            }
            output.push_str(&format!("{}\n", t));
        }

        // Advisories
        if !data.advisories.is_empty() {
            output.push_str(&format!(
                "\n{} ({})\n",
                "Advisories".bold(),
                data.advisories.len()
            ));
            let mut t = self.make_table();
            t.set_header(vec!["Name", "Relationship"]);
            for adv in &data.advisories {
                let rel = adv.relationship.as_deref().unwrap_or("unknown");
                t.add_row(vec![Cell::new(&adv.name), Cell::new(rel)]);
            }
            output.push_str(&format!("{}\n", t));
        }

        output
    }

    pub fn format_contributor(&self, resp: &ContributorResponse) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\n{}\n",
            "Contributor Information".bold().underline()
        ));
        output.push_str(&format!("  Email: {}\n", resp.email.bright_blue()));

        if let Some(ref summary) = resp.data.summary {
            if !summary.repos.is_empty() {
                output.push_str(&format!(
                    "\n{} ({})\n",
                    "Repositories".bold(),
                    summary.repos.len()
                ));
                let mut t = self.make_table();
                t.set_header(vec!["Repository URL"]);
                for repo in &summary.repos {
                    t.add_row(vec![Cell::new(repo)]);
                }
                output.push_str(&format!("{}\n", t));
            }

            if !summary.purls.is_empty() {
                output.push_str(&format!(
                    "\n{} ({})\n",
                    "Packages".bold(),
                    summary.purls.len()
                ));
                let mut t = self.make_table();
                t.set_header(vec!["PURL"]);
                for purl in &summary.purls {
                    t.add_row(vec![Cell::new(purl)]);
                }
                output.push_str(&format!("{}\n", t));
            }
        }

        output
    }

    pub fn format_contributor_security(&self, resp: &ContributorSecurityResponse) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\n{}\n",
            "Contributor Security".bold().underline()
        ));
        output.push_str(&format!("  Email: {}\n", resp.email.bright_blue()));

        let data = &resp.data;
        let mut t = self.make_table();
        t.set_header(vec!["Metric", "Value"]);

        if let Some(v) = data.has_breached_credentials {
            let display = if v && !self.no_color {
                "YES".red().bold().to_string()
            } else if v {
                "YES".to_string()
            } else {
                "No".green().to_string()
            };
            t.add_row(vec![Cell::new("Breach Status"), Cell::new(display)]);
        }

        if let Some(v) = data.signed_commit_ratio {
            t.add_row(vec![
                Cell::new("Signed Commit Ratio"),
                Cell::new(format!("{:.2}", v)),
            ]);
        }

        if let Some(ref ski) = data.signing_key_info {
            if let Some(v) = ski.has_signing_key {
                t.add_row(vec![
                    Cell::new("Has Signing Key"),
                    Cell::new(if v { "Yes" } else { "No" }),
                ]);
            }
            if let Some(v) = ski.key_age_days {
                t.add_row(vec![Cell::new("Key Age (days)"), Cell::new(v)]);
            }
            if let Some(v) = ski.key_change_detected {
                let display = if v && !self.no_color {
                    "YES".red().bold().to_string()
                } else if v {
                    "YES".to_string()
                } else {
                    "No".to_string()
                };
                t.add_row(vec![Cell::new("Key Change Detected"), Cell::new(display)]);
            }
        }

        output.push_str(&format!("{}\n", t));

        // Key changes
        if let Some(ref ski) = data.signing_key_info {
            if !ski.key_changes.is_empty() {
                output.push_str(&format!("\n{}\n", "Key Changes".bold()));
                let mut kt = self.make_table();
                kt.set_header(vec!["Detected At", "Old Key", "New Key"]);
                for kc in &ski.key_changes {
                    kt.add_row(vec![
                        Cell::new(kc.detected_at.as_deref().unwrap_or("-")),
                        Cell::new(kc.old_key_id.as_deref().unwrap_or("-")),
                        Cell::new(kc.new_key_id.as_deref().unwrap_or("-")),
                    ]);
                }
                output.push_str(&format!("{}\n", kt));
            }
        }

        output
    }

    pub fn format_advisory(&self, resp: &AdvisoryResponse) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\n{}\n",
            "Advisory Information".bold().underline()
        ));

        let mut t = self.make_table();
        t.set_header(vec!["Field", "Value"]);
        t.add_row(vec![Cell::new("Name"), Cell::new(&resp.name)]);
        if let Some(ref url) = resp.url {
            t.add_row(vec![Cell::new("URL"), Cell::new(url)]);
        }
        if let Some(ref dt) = resp.created_at {
            t.add_row(vec![Cell::new("Created At"), Cell::new(dt)]);
        }
        output.push_str(&format!("{}\n", t));

        if let Some(ref repos) = resp.repositories {
            if !repos.direct.is_empty() {
                output.push_str(&format!(
                    "\n{} ({})\n",
                    "Direct Repositories".bold().red(),
                    repos.direct.len()
                ));
                let mut rt = self.make_table();
                rt.set_header(vec!["Repository"]);
                for r in &repos.direct {
                    rt.add_row(vec![Cell::new(r.as_str().unwrap_or(&r.to_string()))]);
                }
                output.push_str(&format!("{}\n", rt));
            }
            if !repos.indirect.is_empty() {
                output.push_str(&format!(
                    "\n{} ({})\n",
                    "Indirect Repositories".bold().yellow(),
                    repos.indirect.len()
                ));
                let mut rt = self.make_table();
                rt.set_header(vec!["Repository"]);
                for r in repos.indirect.iter().take(50) {
                    rt.add_row(vec![Cell::new(r.as_str().unwrap_or(&r.to_string()))]);
                }
                if repos.indirect.len() > 50 {
                    output.push_str(&format!("  ... and {} more\n", repos.indirect.len() - 50));
                }
                output.push_str(&format!("{}\n", rt));
            }
        }

        if let Some(ref pkgs) = resp.packages {
            if !pkgs.direct.is_empty() {
                output.push_str(&format!(
                    "\n{} ({})\n",
                    "Direct Packages".bold().red(),
                    pkgs.direct.len()
                ));
                let mut pt = self.make_table();
                pt.set_header(vec!["Package"]);
                for p in &pkgs.direct {
                    pt.add_row(vec![Cell::new(p.as_str().unwrap_or(&p.to_string()))]);
                }
                output.push_str(&format!("{}\n", pt));
            }
            if !pkgs.indirect.is_empty() {
                output.push_str(&format!(
                    "\n{} ({})\n",
                    "Indirect Packages".bold().yellow(),
                    pkgs.indirect.len()
                ));
                let mut pt = self.make_table();
                pt.set_header(vec!["Package"]);
                for p in pkgs.indirect.iter().take(50) {
                    pt.add_row(vec![Cell::new(p.as_str().unwrap_or(&p.to_string()))]);
                }
                if pkgs.indirect.len() > 50 {
                    output.push_str(&format!("  ... and {} more\n", pkgs.indirect.len() - 50));
                }
                output.push_str(&format!("{}\n", pt));
            }
        }

        output
    }

    pub fn format_check_result(&self, result: &AggregateCheckResult) -> String {
        let mut output = String::new();

        // Verdict banner
        let verdict_str = match result.overall_verdict {
            Verdict::Pass => {
                if self.no_color {
                    "PASS".to_string()
                } else {
                    "PASS".green().bold().to_string()
                }
            }
            Verdict::Deny => {
                if self.no_color {
                    "DENY".to_string()
                } else {
                    "DENY".red().bold().to_string()
                }
            }
            Verdict::Review => {
                if self.no_color {
                    "REVIEW".to_string()
                } else {
                    "REVIEW".yellow().bold().to_string()
                }
            }
        };

        output.push_str(&format!("\nVerdict: {}\n", verdict_str));

        // Show warnings
        for w in &result.warnings {
            output.push_str(&format!("  [WARN] {}\n", w));
        }

        // Show matches
        if !result.all_matches.is_empty() {
            output.push_str(&format!("\n{}\n", "Rule Matches".bold()));
            let mut t = self.make_table();
            t.set_header(vec!["Rule", "Action", "Package", "Reason"]);
            for m in &result.all_matches {
                let action_str = match m.action {
                    Action::Deny => {
                        if self.no_color {
                            "DENY".to_string()
                        } else {
                            "DENY".red().bold().to_string()
                        }
                    }
                    Action::Review => {
                        if self.no_color {
                            "REVIEW".to_string()
                        } else {
                            "REVIEW".yellow().bold().to_string()
                        }
                    }
                    Action::Warn => {
                        if self.no_color {
                            "WARN".to_string()
                        } else {
                            "WARN".yellow().to_string()
                        }
                    }
                    Action::Info => {
                        if self.no_color {
                            "INFO".to_string()
                        } else {
                            "INFO".cyan().to_string()
                        }
                    }
                    Action::Allow => {
                        if self.no_color {
                            "ALLOW".to_string()
                        } else {
                            "ALLOW".green().to_string()
                        }
                    }
                };
                t.add_row(vec![
                    Cell::new(&m.rule_name),
                    Cell::new(action_str),
                    Cell::new(truncate_purl(&m.purl, 60)),
                    Cell::new(&m.reason),
                ]);
            }
            output.push_str(&format!("{}\n", t));
        } else if result.package_results.is_empty() {
            output.push_str("  No rules matched. PASS.\n");
        }

        output
    }

    pub fn format_scan_summary(
        &self,
        total: usize,
        succeeded: usize,
        failed: usize,
        advisories_count: usize,
    ) -> String {
        let mut output = String::new();
        output.push_str(&format!("\n{}\n", "Scan Summary".bold().underline()));
        output.push_str(&format!("  Total packages: {}\n", total));
        output.push_str(&format!("  Scanned:        {}\n", succeeded));
        output.push_str(&format!("  Failed:         {}\n", failed));
        output.push_str(&format!("  With advisories:{}\n", advisories_count));
        output
    }
}

fn truncate_purl(purl: &str, max_len: usize) -> String {
    if purl.len() <= max_len {
        purl.to_string()
    } else {
        let half = (max_len - 3) / 2;
        format!("{}...{}", &purl[..half], &purl[purl.len() - half..])
    }
}
