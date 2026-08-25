//! `writ doctor` — environment/dependency check before a build.
//!
//! Verifies what tpt-writ actually needs at build time: a working Rust
//! toolchain and the sibling `tpt-telos` checkout that provides
//! `tpt-telos-sdk` as a path dependency. No network access required.

/// One environment check and its outcome.
#[derive(Debug)]
pub struct Check {
    /// Human-readable name of the requirement.
    pub name: &'static str,
    /// What went wrong, if anything (`None` == pass).
    pub problem: Option<String>,
}

fn sibling_telos() -> Option<std::path::PathBuf> {
    std::path::Path::new("../tpt-telos").canonicalize().ok()
}

/// Run all checks; return them for reporting. Empty problems == healthy.
pub fn run_checks() -> Vec<Check> {
    let mut checks = Vec::new();

    // Toolchain presence (version parsing kept loose on purpose).
    match std::process::Command::new("cargo")
        .arg("--version")
        .output()
    {
        Ok(out) if out.status.success() => {
            checks.push(Check {
                name: "cargo",
                problem: None,
            });
        }
        _ => checks.push(Check {
            name: "cargo",
            problem: Some("cargo not found on PATH".to_string()),
        }),
    }
    match std::process::Command::new("rustc")
        .arg("--version")
        .output()
    {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
            eprintln!("  rustc: {version}");
            checks.push(Check {
                name: "rustc",
                problem: None,
            });
        }
        _ => checks.push(Check {
            name: "rustc",
            problem: Some("rustc not found on PATH".to_string()),
        }),
    }

    // Sibling checkout layout (see README "Prerequisites").
    match sibling_telos() {
        None => checks.push(Check {
            name: "sibling tpt-telos checkout",
            problem: Some(
                "../tpt-telos not found; clone tpt-telos next to this repo \
                 (see README Prerequisites)"
                    .to_string(),
            ),
        }),
        Some(root) => {
            let sdk = root.join("crates/tpt-telos-sdk/Cargo.toml");
            if sdk.exists() {
                checks.push(Check {
                    name: "sibling tpt-telos checkout",
                    problem: None,
                });
            } else {
                checks.push(Check {
                    name: "sibling tpt-telos checkout",
                    problem: Some(format!(
                        "{} is missing crates/tpt-telos-sdk — is this a full clone?",
                        root.display()
                    )),
                });
            }

            let codegen = root.join("crates/tpt-telos-codegen/src/proof.rs");
            if !codegen.exists() {
                checks.push(Check {
                    name: "telos-codegen proof module",
                    problem: Some("crates/tpt-telos-codegen missing from ../tpt-telos".to_string()),
                });
            } else {
                checks.push(Check {
                    name: "telos-codegen proof module",
                    problem: None,
                });
            }
        }
    }

    checks
}

/// Print the check report; `true` when everything passed.
pub fn report(checks: &[Check]) -> bool {
    println!("writ doctor");
    let mut healthy = true;
    for c in checks {
        match &c.problem {
            None => println!("  [ok]   {}", c.name),
            Some(problem) => {
                healthy = false;
                println!("  [FAIL] {}: {problem}", c.name);
            }
        }
    }
    println!(
        "{}",
        if healthy {
            "environment looks good — the writ pipeline can run"
        } else {
            "environment has problems — fix the FAIL lines above"
        }
    );
    healthy
}
