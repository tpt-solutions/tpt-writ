//! Unit tests: guard decisions and the signed-manifest load path.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use tpt_telos_codegen::proof::{to_json, FuncProof, ProofManifest};
use tpt_writ_core::{ConservativeDerivation, RightDerivation, WritGrant, WritRight};

use crate::{AccessMode, DenialReason, WritGuard, WritGuardError};

/// A manifest like the pipeline produces, without running the full loop.
fn manifest_with(functions: &[(&str, bool, usize)]) -> ProofManifest {
    let mut map = BTreeMap::new();
    for (name, verified, checks) in functions {
        map.insert(
            (*name).to_string(),
            FuncProof {
                verified: *verified,
                conclusions_checked: *checks,
                conclusions_passed: if *verified { *checks } else { 0 },
                used_interval_bounding: false,
                resource_accesses: Vec::new(),
            },
        );
    }
    ProofManifest {
        schema_version: "1",
        source_hash: format!("sha256:{}", "ab".repeat(32)),
        verified_at: "2026-01-01T00:00:00Z".to_string(),
        functions: map,
        manifest_hash: format!("sha256:{}", "cd".repeat(32)),
    }
}

/// A second `RightDerivation` impl — exists to prove the trait boundary is
/// real and that `WritGuard` does not care which derivation backs it.
struct ScopedDerivation(BTreeMap<String, WritRight>);

impl RightDerivation for ScopedDerivation {
    fn derive(&self, manifest: &ProofManifest, function: &str) -> WritGrant {
        WritGrant {
            function_name: function.to_string(),
            right: self.0.get(function).cloned().unwrap_or(WritRight::Pure),
            manifest_hash: tpt_writ_core::manifest_hash_bytes(manifest),
            issued_at: std::time::SystemTime::now(),
        }
    }
}

// -- check_call decisions --------------------------------------------------

#[test]
fn unknown_tool_is_denied_with_no_held_grant() {
    let guard = WritGuard::from_manifest(&manifest_with(&[]), ConservativeDerivation);
    let err = guard
        .check_call("ghost", "filesystem:/data", AccessMode::Read)
        .expect_err("unknown tool must be denied");
    assert_eq!(err.held, None);
    assert_eq!(err.reason, DenialReason::NoGrant);
    assert!(err.to_string().contains("no grant"), "{err}");
}

#[test]
fn coarse_write_grant_covers_every_class_and_mode() {
    // ConservativeDerivation maps any proved obligation to Write{"*"}.
    let guard = WritGuard::from_manifest(
        &manifest_with(&[("deposit", true, 2)]),
        ConservativeDerivation,
    );
    for mode in [AccessMode::Read, AccessMode::Write] {
        for class in ["filesystem:/data", "db:users", "net:anything"] {
            guard
                .check_call("deposit", class, mode)
                .unwrap_or_else(|e| panic!("coarse grant must allow {class}/{mode}: {e}"));
        }
    }
}

#[test]
fn tool_absent_from_manifest_is_denied_even_when_others_are_gated() {
    let guard = WritGuard::from_manifest(
        &manifest_with(&[("deposit", true, 2), ("unverified_fn", false, 1)]),
        ConservativeDerivation,
    );
    // The unverified function earned no grant...
    assert!(!guard.grants().contains_key("unverified_fn"));
    let err = guard
        .check_call("unverified_fn", "*", AccessMode::Write)
        .expect_err("a failed proof earns nothing");
    assert_eq!(err.reason, DenialReason::NoGrant);
}

#[test]
fn scoped_rights_enforce_class_and_mode() {
    let mut rights = BTreeMap::new();
    rights.insert(
        "read_data".to_string(),
        WritRight::Read {
            resource_class: "filesystem:/data".to_string(),
        },
    );
    rights.insert(
        "write_db".to_string(),
        WritRight::Write {
            resource_class: "db:users".to_string(),
        },
    );
    rights.insert("calculator".to_string(), WritRight::Pure);
    // The guard derives grants only for functions the manifest attests, so
    // the fixture must list them (the scoped derivation then narrows each).
    let manifest = manifest_with(&[
        ("read_data", true, 1),
        ("write_db", true, 2),
        ("calculator", true, 0),
    ]);
    let guard = WritGuard::from_manifest(&manifest, ScopedDerivation(rights));

    // Read held, read attempted, matching class: allowed.
    guard
        .check_call("read_data", "filesystem:/data", AccessMode::Read)
        .expect("matching read must pass");
    // Read held, write attempted, matching class: denied precisely.
    let err = guard
        .check_call("read_data", "filesystem:/data", AccessMode::Write)
        .expect_err("write under a read grant");
    assert_eq!(
        err.reason,
        DenialReason::ReadHeldForWriteAttempt {
            resource_class: "filesystem:/data".to_string()
        }
    );
    // Read held, read attempted, wrong class: denied as class mismatch.
    let err = guard
        .check_call("read_data", "db:users", AccessMode::Read)
        .expect_err("cross-class read");
    assert_eq!(
        err.reason,
        DenialReason::WrongResourceClass {
            held_class: "filesystem:/data".to_string()
        }
    );

    // Write held, both modes on the class: allowed.
    for mode in [AccessMode::Read, AccessMode::Write] {
        guard
            .check_call("write_db", "db:users", mode)
            .unwrap_or_else(|e| panic!("write grant covers {mode}: {e}"));
    }
    // Write held, other class: denied.
    let err = guard
        .check_call("write_db", "filesystem:/data", AccessMode::Write)
        .expect_err("cross-class write");
    assert!(matches!(
        err.reason,
        DenialReason::WrongResourceClass { .. }
    ));

    // Pure holds: any resource access oversteps.
    let err = guard
        .check_call("calculator", "net:api", AccessMode::Read)
        .expect_err("pure grant covers no resource access");
    assert_eq!(
        err.held,
        Some(WritRight::Pure),
        "denial must state what was held"
    );
    assert_eq!(err.reason, DenialReason::PureHoldsNoResourceAccess);
    assert!(err.to_string().contains("Pure"), "{err}");
}

// -- signed-manifest load path ---------------------------------------------

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[test]
fn signed_manifest_round_trips_into_a_working_guard() {
    let json = to_json(&manifest_with(&[("deposit", true, 2)]));
    let key = keypair(7);
    let sig: Signature = key.sign(json.as_bytes());
    let pubkey: VerifyingKey = key.verifying_key();

    let guard = WritGuard::from_signed_manifest(&json, &pubkey, &sig, ConservativeDerivation)
        .expect("signed manifest loads");
    assert!(guard.grants().contains_key("deposit"));
    guard
        .check_call("deposit", "fs:any", AccessMode::Write)
        .expect("grant enforced after signature check");
}

#[test]
fn tampered_document_fails_signature_check() {
    let json = to_json(&manifest_with(&[("f", true, 0)]));
    let key = keypair(7);
    let sig = key.sign(json.as_bytes());
    let pubkey = key.verifying_key();

    let tampered = json.replace("\"schema_version\": \"1\"", "\"schema_version\": \"99\"");
    let err = WritGuard::from_signed_manifest(&tampered, &pubkey, &sig, ConservativeDerivation)
        .expect_err("edited document invalidates its signature");
    assert!(matches!(err, WritGuardError::InvalidSignature), "{err:?}");
}

#[test]
fn wrong_key_fails_signature_check() {
    let json = to_json(&manifest_with(&[("f", true, 0)]));
    let signer = keypair(1);
    let other = keypair(2);
    let sig = signer.sign(json.as_bytes());

    let err = WritGuard::from_signed_manifest(
        &json,
        &other.verifying_key(),
        &sig,
        ConservativeDerivation,
    )
    .expect_err("signature from a different key must not verify");
    assert!(matches!(err, WritGuardError::InvalidSignature), "{err:?}");
}

// -- Phase 4 swap-in verification -------------------------------------------
//
// The checklist's actual ask: confirm `WritGuard<D>`/`check_call` need zero
// source changes when the derivation swaps from `ConservativeDerivation` to
// `ResourceAwareDerivation`. Both guards below are built from the exact same
// manifest through the exact same `WritGuard::from_manifest` + `check_call`
// path -- only the type parameter differs.

fn manifest_with_one_resource_access(
    name: &str,
    checks: usize,
    class: &str,
    mode: tpt_writ_core::AccessMode,
) -> ProofManifest {
    let mut map = BTreeMap::new();
    map.insert(
        name.to_string(),
        FuncProof {
            verified: true,
            conclusions_checked: checks,
            conclusions_passed: checks,
            used_interval_bounding: false,
            resource_accesses: vec![(class.to_string(), mode)],
        },
    );
    ProofManifest {
        schema_version: "1",
        source_hash: format!("sha256:{}", "ab".repeat(32)),
        verified_at: "2026-01-01T00:00:00Z".to_string(),
        functions: map,
        manifest_hash: format!("sha256:{}", "cd".repeat(32)),
    }
}

#[test]
fn resource_aware_derivation_slots_into_the_same_guard_type() {
    use tpt_writ_core::ResourceAwareDerivation;

    let manifest =
        manifest_with_one_resource_access("bump", 2, "db:users", tpt_writ_core::AccessMode::Write);

    // Same manifest, same `check_call` path, only the derivation differs.
    let conservative = WritGuard::from_manifest(&manifest, ConservativeDerivation);
    let aware = WritGuard::from_manifest(&manifest, ResourceAwareDerivation);

    // Conservative can't narrow past Write{"*"}: every class/mode passes.
    conservative
        .check_call("bump", "anything:at-all", AccessMode::Write)
        .expect("coarse grant allows any class");

    // Resource-aware narrowed it to exactly Write{"db:users"}: the real
    // class/mode passes, everything else the coarse grant allowed is now
    // correctly denied -- strictly stricter, never looser.
    aware
        .check_call("bump", "db:users", AccessMode::Write)
        .expect("scoped grant allows its own class/mode");
    let err = aware
        .check_call("bump", "filesystem:/data", AccessMode::Write)
        .expect_err("scoped grant must not cover an unrelated class");
    assert!(matches!(
        err.reason,
        DenialReason::WrongResourceClass { .. }
    ));
}

#[test]
fn resource_aware_pure_and_unknown_tool_behave_identically_to_conservative() {
    use tpt_writ_core::ResourceAwareDerivation;

    // A vacuous proof and an absent tool are derivation-independent by
    // construction (both rules agree on Pure and on "no grant" respectively),
    // so both guards must agree here too.
    let manifest = manifest_with(&[("noop", true, 0)]);

    let conservative = WritGuard::from_manifest(&manifest, ConservativeDerivation);
    assert_eq!(conservative.grants()["noop"].right, WritRight::Pure);
    let err = conservative
        .check_call("ghost", "anything", AccessMode::Read)
        .expect_err("unknown tool denied under conservative derivation");
    assert_eq!(err.reason, DenialReason::NoGrant);

    let aware = WritGuard::from_manifest(&manifest, ResourceAwareDerivation);
    assert_eq!(aware.grants()["noop"].right, WritRight::Pure);
    let err = aware
        .check_call("ghost", "anything", AccessMode::Read)
        .expect_err("unknown tool denied under resource-aware derivation too");
    assert_eq!(err.reason, DenialReason::NoGrant);
}
