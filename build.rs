use std::process::Command;

fn main() {
    // Git hash
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=PROVENANCE_GIT_HASH={}", git_hash);

    // Build date
    let build_date = chrono_date();
    println!("cargo:rustc-env=PROVENANCE_BUILD_DATE={}", build_date);

    // Rustc version
    let rustc_version = Command::new("rustc")
        .args(["--version"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let full = String::from_utf8_lossy(&o.stdout).trim().to_string();
                // Extract just the version number
                full.split_whitespace().nth(1).map(|s| s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=PROVENANCE_RUSTC_VERSION={}", rustc_version);
}

fn chrono_date() -> String {
    // Simple date without chrono dependency in build script
    Command::new("date")
        .args(["+%Y-%m-%d"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}
