//! `writ` — the tpt-writ command line: verify, guard, diff, doctor.
//!
//! Deliberately mirrors nexus's CLI naming so the mental model transfers:
//! same verbs, different target (MCP tool-call scopes instead of Archon page
//! capabilities).

pub mod diff;
pub mod doctor;
pub mod guard;
pub mod relay;
pub mod signing;

use std::collections::BTreeMap;

use tpt_telos_sdk::{compile_static, StaticAgent, VerifiedArtifact};
use tpt_writ_core::{derive_all, ConservativeDerivation, RightDerivation, WritRight};

/// Compile a `.telos` source and return the fully-orchestrated artifact.
///
/// Fails closed downstream: a source whose functions do not all verify still
/// produces an artifact (verification failure is data, not error), but only
/// *verified* functions earn grants — see [`tpt_writ_core::derive_all`].
pub fn compile_service(source: &[u8]) -> anyhow::Result<VerifiedArtifact> {
    compile_static(source, &StaticAgent::new()).map_err(|e| anyhow::anyhow!("pipeline failed: {e}"))
}

/// The derived rights for every verified function in the artifact, under the
/// given [`RightDerivation`].
///
/// Generic from day one for the same reason `WritGuard<D>` is (see
/// `tpt-writ-mcp`): swapping `ConservativeDerivation` for
/// `ResourceAwareDerivation` (or any future derivation) costs nothing here —
/// [`derive_rights`] is the thin, derivation-agnostic default every CLI
/// command actually calls.
pub fn derive_rights_with<D: RightDerivation>(
    artifact: &VerifiedArtifact,
    derivation: &D,
) -> BTreeMap<String, WritRight> {
    derive_all(derivation, &artifact.manifest)
        .into_iter()
        .map(|(name, grant)| (name, grant.right))
        .collect()
}

/// The derived rights for every verified function in the artifact, under the
/// v0.1 default ([`ConservativeDerivation`]). What `writ verify`/`writ diff`
/// actually call; see [`derive_rights_with`] for the derivation-generic form.
pub fn derive_rights(artifact: &VerifiedArtifact) -> BTreeMap<String, WritRight> {
    derive_rights_with(artifact, &ConservativeDerivation)
}

/// Render the right table as aligned text rows (`name  right`).
pub fn format_right_table(rights: &BTreeMap<String, WritRight>) -> String {
    let width = rights.keys().map(String::len).max().unwrap_or(0);
    rights
        .iter()
        .map(|(name, right)| format!("  {name:<width$}  {right}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn read_bytes(path: &str) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))
}

// ---------------------------------------------------------------------------
// writ verify
// ---------------------------------------------------------------------------

/// `writ verify <source>` — compile, derive, print the grant table.
///
/// Exit codes: 0 = all functions verified; 1 = pipeline failure or any
/// unverified function (its name is printed; it earns no grant).
pub fn run_verify(source_path: &str) -> i32 {
    let source = match read_bytes(source_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("writ verify: {e}");
            return 1;
        }
    };
    let artifact = match compile_service(&source) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("writ verify: {e}");
            return 1;
        }
    };

    let verified = artifact.outcomes.iter().filter(|o| o.verified).count();
    let total = artifact.outcomes.len();
    println!("{source_path}: {verified}/{total} functions verified");

    let rights = derive_rights(&artifact);
    println!("\nMCP grants derived from the attested proof:");
    println!("{}", format_right_table(&rights));

    if verified < total {
        let failed: Vec<&str> = artifact
            .outcomes
            .iter()
            .filter(|o| !o.verified)
            .map(|o| o.func_name.as_str())
            .collect();
        eprintln!("\nUNVERIFIED (earn no grant): {}", failed.join(", "));
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// writ diff
// ---------------------------------------------------------------------------

/// `writ diff <before> <after>` — capability security-regression view.
///
/// Exit codes: 0 = no change or a narrowing; 1 = a widening; 2 = a source
/// failed to compile (cannot compare).
pub fn run_diff(before_path: &str, after_path: &str) -> i32 {
    let derive = |path: &str| -> anyhow::Result<BTreeMap<String, WritRight>> {
        let src = read_bytes(path)?;
        let artifact = compile_service(&src).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        Ok(derive_rights(&artifact))
    };

    let (before, after) = match (derive(before_path), derive(after_path)) {
        (Ok(b), Ok(a)) => (b, a),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("writ diff: {e}");
            return 2;
        }
    };

    println!("capability surface {before_path} -> {after_path}:");
    let deltas = diff::classify(&before, &after);
    println!("{}", diff::format_deltas(&deltas));

    if diff::any_widening(&deltas) {
        println!("\nVERDICT: WIDENED — this change grants more than before");
        1
    } else {
        println!("\nverdict: no widening");
        0
    }
}

// ---------------------------------------------------------------------------
// writ doctor / writ guard
// ---------------------------------------------------------------------------

/// `writ doctor` — true when every check passed.
pub fn doctor_ok() -> bool {
    doctor::report(&doctor::run_checks())
}

/// Options for [`run_guard`], mirroring the `guard` subcommand's flags.
pub struct GuardOptions {
    /// Path to the telos-proof.json manifest document.
    pub manifest_path: String,
    /// Optional .telos source enabling the full VALIDATE hash check.
    pub source_path: Option<String>,
    /// Optional (`--pubkey`, `--signature`) pair; the signature may be hex or
    /// a path to a file containing hex.
    pub pubkey_and_sig: Option<(String, String)>,
    /// Target MCP server program.
    pub target_program: String,
    /// Arguments for the target program.
    pub target_args: Vec<String>,
    /// Tools existence-checked only (the right policy for Pure tools).
    pub allow_tools: Vec<String>,
}

/// `writ guard` — spawn the target MCP server and relay its traffic through
/// a [`tpt_writ_mcp::WritGuard`]. Exit 0 on clean shutdown, 1 on any failure.
pub fn run_guard(opts: GuardOptions) -> i32 {
    // Resolve --signature early: bare hex, or contents of a .sig file.
    let sig_hex_owned = opts.pubkey_and_sig.as_ref().map(|(p, s)| {
        let sig = match std::fs::read_to_string(s) {
            Ok(contents) => contents,
            Err(_) => s.clone(), // not a path — treat as literal hex
        };
        (p.clone(), sig)
    });

    let loaded = (|| {
        let manifest_bytes = read_bytes(&opts.manifest_path)?;
        let source_bytes = match &opts.source_path {
            Some(p) => Some(read_bytes(p)?),
            None => None,
        };
        let pk_sig = sig_hex_owned
            .as_ref()
            .map(|(p, s)| (p.as_str(), s.as_str()));
        guard::load_manifest(&manifest_bytes, source_bytes.as_deref(), pk_sig)
            .map_err(|e| anyhow::anyhow!("{e}"))
    })();

    let loaded = match loaded {
        Ok(l) => l,
        Err(e) => {
            eprintln!("writ guard: {e}");
            return 1;
        }
    };

    println!(
        "writ guard: manifest accepted via [{}], guarding `{}`",
        [
            ("source-hash", loaded.validated_by_source),
            ("signature", loaded.verified_signature),
        ]
        .into_iter()
        .filter_map(|(n, ok)| ok.then_some(n))
        .collect::<Vec<_>>()
        .join(" + "),
        opts.target_program
    );

    let runtime_guard = guard::build_guard(&loaded);
    for (name, grant) in runtime_guard.grants() {
        println!("  {name} -> {}", grant.right);
    }

    let mut child = match guard::spawn_target(&opts.target_program, &opts.target_args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("writ guard: {e}");
            return 1;
        }
    };
    let stdin = child.stdin.take().expect("stdin piped");
    let stdout = child.stdout.take().expect("stdout piped");

    let mut policy = relay::GuardPolicy::default();
    for tool in &opts.allow_tools {
        policy.set(tool.clone(), relay::Attempt::Exists);
    }

    let r = relay::Relay {
        guard: runtime_guard,
        policy,
    };
    let agent_in = std::io::stdin();
    let agent_out = std::io::stdout();
    let result = r.serve(agent_in.lock(), agent_out, stdin, stdout);

    match result {
        Ok(_) => {
            let _ = child.wait();
            0
        }
        Err(e) => {
            eprintln!("writ guard: relay error: {e}");
            let _ = child.kill();
            let _ = child.wait();
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_writ_core::ResourceAwareDerivation;

    const MULTI_RESOURCE_TELOS: &str = include_str!("../../../examples/multi_resource.telos");

    /// Phase 4 swap-in verification, CLI layer: `derive_rights_with` is
    /// generic over the derivation, so pointing it at `ResourceAwareDerivation`
    /// requires no change to this crate's structure -- only the argument
    /// passed at the call site. `derive_rights` (what `writ verify`/`writ
    /// diff` actually call) is unaffected and keeps its `ConservativeDerivation`
    /// default.
    #[test]
    fn derive_rights_with_generalizes_to_resource_aware_derivation() {
        let artifact = compile_service(MULTI_RESOURCE_TELOS.as_bytes())
            .expect("multi_resource.telos must compile and verify");

        let conservative = derive_rights(&artifact);
        for right in conservative.values() {
            assert_eq!(
                *right,
                WritRight::Write {
                    resource_class: "*".to_string()
                },
                "the v0.1 default is unaffected by this generalization"
            );
        }

        let aware = derive_rights_with(&artifact, &ResourceAwareDerivation);
        assert_eq!(
            aware["peek_sender"],
            WritRight::Read {
                resource_class: "db:senders".to_string()
            }
        );
        assert_eq!(
            aware["bump_sender"],
            WritRight::Write {
                resource_class: "db:senders".to_string()
            }
        );
        // Touches two tagged classes / an untagged invariant: both still
        // fail closed to the coarse right, same as ConservativeDerivation.
        assert_eq!(aware["transfer"], conservative["transfer"]);
        assert_eq!(aware["audit"], conservative["audit"]);
    }

    const MULTI_RESOURCE_V2_TELOS: &str = include_str!("../../../examples/multi_resource-v2.telos");

    /// `writ diff`'s Phase 4 extension: `diff::classify`/`any_widening` are
    /// already fully generic over `WritRight`'s resource classes (see
    /// `diff.rs`'s own unit tests), so this needs no change to `diff.rs`
    /// itself -- only proof that real `ResourceAwareDerivation`-derived
    /// rights from two real fixture versions flow through it correctly.
    ///
    /// v2's `transfer` drops the `Receiver` parameter entirely, so under
    /// `ResourceAwareDerivation` it narrows from the multi-class fallback
    /// `Write{"*"}` to the single-class `Write{"db:senders"}`. Under
    /// `ConservativeDerivation` the exact same source change is invisible
    /// (both versions show `Write{"*"}`) -- resource-aware diffing sees a
    /// real narrowing/widening that the coarse derivation cannot.
    #[test]
    fn diff_sees_a_resource_class_narrowing_invisible_to_conservative_derivation() {
        let v1 = compile_service(MULTI_RESOURCE_TELOS.as_bytes()).expect("v1 compiles");
        let v2 = compile_service(MULTI_RESOURCE_V2_TELOS.as_bytes()).expect("v2 compiles");

        // Conservative derivation: no visible change at all.
        let conservative_deltas = diff::classify(&derive_rights(&v1), &derive_rights(&v2));
        assert!(
            !diff::any_widening(&conservative_deltas),
            "conservative derivation can't see this change"
        );
        assert!(
            conservative_deltas
                .iter()
                .all(|(_, d)| matches!(d, diff::Delta::Unchanged(_))),
            "every function must look unchanged under the coarse fallback: {conservative_deltas:?}"
        );

        // Resource-aware derivation: v1 -> v2 is a narrowing...
        let aware_v1 = derive_rights_with(&v1, &ResourceAwareDerivation);
        let aware_v2 = derive_rights_with(&v2, &ResourceAwareDerivation);
        let forward = diff::classify(&aware_v1, &aware_v2);
        assert!(
            !diff::any_widening(&forward),
            "dropping a resource class must not register as a widening"
        );
        assert!(forward
            .iter()
            .any(|(n, d)| n == "transfer" && matches!(d, diff::Delta::Narrowed { .. })));

        // ...and v2 -> v1 (re-adding the second class) is the widening.
        let backward = diff::classify(&aware_v2, &aware_v1);
        assert!(diff::any_widening(&backward), "re-adding a class widens");
        assert!(backward
            .iter()
            .any(|(n, d)| n == "transfer" && matches!(d, diff::Delta::Widened { .. })));
    }
}
