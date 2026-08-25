//! Unit tests: derivation correctness and manifest-hash tamper detection.

use std::collections::BTreeMap;
use std::time::SystemTime;

use tpt_telos_codegen::proof::{generate_manifest, to_json, FuncProof, ProofManifest};

use crate::error::WritError;
use crate::validate::{manifest_hash_bytes, try_manifest_hash_bytes, validate_manifest};

use crate::{
    derive_all, AccessMode, ConservativeDerivation, ResourceAwareDerivation, RightDerivation,
    WritRight,
};

/// Build a manifest like the pipeline would, without running the whole
/// parse/transpile/verify loop — every `ProofManifest` field is public.
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

/// `(name, verified, conclusions_checked, resource_accesses)` — one fixture
/// function's shape, for [`manifest_with_resources`].
type FuncFixture<'a> = (&'a str, bool, usize, &'a [(&'a str, AccessMode)]);

/// Like [`manifest_with`], but each function also carries the
/// `resource_accesses` a real `tpt-telos-ir` extraction would attach.
fn manifest_with_resources(functions: &[FuncFixture]) -> ProofManifest {
    let mut map = BTreeMap::new();
    for (name, verified, checks, accesses) in functions {
        map.insert(
            (*name).to_string(),
            FuncProof {
                verified: *verified,
                conclusions_checked: *checks,
                conclusions_passed: if *verified { *checks } else { 0 },
                used_interval_bounding: false,
                resource_accesses: accesses
                    .iter()
                    .map(|(class, mode)| (class.to_string(), *mode))
                    .collect(),
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

fn coarse_write() -> WritRight {
    WritRight::Write {
        resource_class: "*".to_string(),
    }
}

// -- derivation correctness ----------------------------------------------

#[test]
fn vacuous_proof_derives_pure() {
    let m = manifest_with(&[("noop", true, 0)]);
    assert_eq!(
        ConservativeDerivation.derive(&m, "noop").right,
        WritRight::Pure
    );
}

#[test]
fn proved_obligation_falls_back_to_coarse_write() {
    // A function with real obligations (e.g. `ensures balance == old +
    // amount`) cannot be argued pure from the manifest alone -> fail closed
    // to the coarse right.
    let m = manifest_with(&[("deposit", true, 3)]);
    assert_eq!(
        ConservativeDerivation.derive(&m, "deposit").right,
        coarse_write()
    );
}

#[test]
fn interval_bounded_proof_also_falls_back_to_coarse_write() {
    let mut m = manifest_with(&[("approx", true, 1)]);
    m.functions
        .get_mut("approx")
        .unwrap()
        .used_interval_bounding = true;
    assert_eq!(
        ConservativeDerivation.derive(&m, "approx").right,
        coarse_write()
    );
}

#[test]
fn unknown_function_fails_closed_to_coarse_write() {
    let m = manifest_with(&[("known", true, 0)]);
    assert_eq!(
        ConservativeDerivation.derive(&m, "never_heard_of_it").right,
        coarse_write()
    );
}

#[test]
fn unverified_function_is_skipped_by_derive_all() {
    let m = manifest_with(&[("good", true, 0), ("bad", false, 2)]);
    let grants = derive_all(&ConservativeDerivation, &m);
    assert_eq!(grants["good"].right, WritRight::Pure);
    assert!(!grants.contains_key("bad"), "a failed proof earns no grant");
}

#[test]
fn grant_carries_decoded_manifest_hash_and_timestamp() {
    let m = manifest_with(&[("f", true, 0)]);
    let grant = ConservativeDerivation.derive(&m, "f");
    assert_eq!(grant.manifest_hash, [0xcd; 32]);
    assert_eq!(grant.function_name, "f");
    assert!(grant.issued_at <= SystemTime::now());
}

// -- manifest-hash tampering -----------------------------------------------

#[test]
fn intact_manifest_validates_against_its_source() {
    let m = generate_manifest(b"module M {}", &[]);
    let json = to_json(&m);
    let decoded = validate_manifest(&json, b"module M {}").expect("intact manifest validates");
    assert_eq!(decoded, manifest_hash_bytes(&m));
}

#[test]
fn mutated_manifest_is_rejected() {
    let m = generate_manifest(b"module M {}", &[]);
    let mut json = to_json(&m);
    // Tamper with a payload field (telos's own tamper test uses the same
    // edit): bumping schema_version changes the document, so the re-derived
    // hash no longer matches.
    json = json.replace("\"schema_version\": \"1\"", "\"schema_version\": \"99\"");
    assert_ne!(json, to_json(&m), "edit must have changed the document");
    let err =
        validate_manifest(&json, b"module M {}").expect_err("edited manifest must be rejected");
    assert!(
        matches!(err, WritError::ManifestTampered { .. }),
        "wrong error: {err:?}"
    );
}

#[test]
fn drifted_source_is_rejected() {
    // Internally consistent manifest, but attested for a different source.
    let m = generate_manifest(b"module M {}", &[]);
    let json = to_json(&m);
    let err = validate_manifest(&json, b"module M { changed }")
        .expect_err("source drift must be rejected");
    assert!(matches!(err, WritError::SourceDrift { .. }), "{err:?}");
}

#[test]
fn stripped_manifest_hash_is_rejected_as_tampering() {
    let m = generate_manifest(b"module M {}", &[]);
    let json = to_json(&m);
    let stripped = json.replace(
        &format!("\"manifest_hash\": \"{}\"", m.manifest_hash),
        "\"manifest_hash\": \"\"",
    );
    // Blanking the hash changes the document, so the re-derived hash no
    // longer matches what the (blank) field claims -> tamper, not absence.
    let err =
        validate_manifest(&stripped, b"module M {}").expect_err("blanked hash must be rejected");
    assert!(
        matches!(
            &err,
            WritError::ManifestTampered { expected, .. } if expected.is_empty()
        ),
        "wrong error: {err:?}"
    );
}

// Note: there is no dedicated "missing manifest_hash" test here. A document
// lacking the field fails inside verify_manifest as tampering/source-drift
// before our defensive MissingManifestHash branch can fire.

#[test]
fn malformed_hash_field_fails_closed() {
    let mut m = manifest_with(&[("f", true, 0)]);
    m.manifest_hash = "sha256:not-a-hash".to_string();
    assert!(try_manifest_hash_bytes(&m).is_err());
}

#[test]
fn different_source_yields_different_hash() {
    let a = generate_manifest(b"module A {}", &[]);
    let b = generate_manifest(b"module B {}", &[]);
    assert_ne!(a.manifest_hash, b.manifest_hash);
}

// -- ResourceAwareDerivation (Phase 4) --------------------------------------

#[test]
fn resource_aware_vacuous_proof_still_derives_pure() {
    // Same rule as ConservativeDerivation, independent of resource_accesses.
    let m = manifest_with_resources(&[("noop", true, 0, &[])]);
    assert_eq!(
        ResourceAwareDerivation.derive(&m, "noop").right,
        WritRight::Pure
    );
}

#[test]
fn resource_aware_single_class_read_is_scoped_read() {
    let m = manifest_with_resources(&[("peek", true, 1, &[("db:users", AccessMode::Read)])]);
    assert_eq!(
        ResourceAwareDerivation.derive(&m, "peek").right,
        WritRight::Read {
            resource_class: "db:users".to_string()
        }
    );
}

#[test]
fn resource_aware_single_class_write_is_scoped_write() {
    let m = manifest_with_resources(&[("bump", true, 2, &[("db:users", AccessMode::Write)])]);
    assert_eq!(
        ResourceAwareDerivation.derive(&m, "bump").right,
        WritRight::Write {
            resource_class: "db:users".to_string()
        }
    );
}

#[test]
fn resource_aware_untagged_state_falls_back_to_coarse_write() {
    // Verified, has real obligations, but the extraction found no tagged
    // resource class at all (untagged state, or none touched).
    let m = manifest_with_resources(&[("mystery", true, 1, &[])]);
    assert_eq!(
        ResourceAwareDerivation.derive(&m, "mystery").right,
        coarse_write()
    );
}

#[test]
fn resource_aware_multi_class_falls_back_to_coarse_write() {
    // v0.1's WritRight vocabulary can't name "this class AND that class",
    // so touching two tagged classes still fails closed to the coarse right.
    let m = manifest_with_resources(&[(
        "transfer",
        true,
        2,
        &[
            ("db:senders", AccessMode::Write),
            ("db:receivers", AccessMode::Write),
        ],
    )]);
    assert_eq!(
        ResourceAwareDerivation.derive(&m, "transfer").right,
        coarse_write()
    );
}

#[test]
fn resource_aware_unverified_function_fails_closed() {
    let m = manifest_with_resources(&[("bad", false, 1, &[("db:users", AccessMode::Read)])]);
    assert_eq!(
        ResourceAwareDerivation.derive(&m, "bad").right,
        coarse_write()
    );
}

#[test]
fn resource_aware_unknown_function_fails_closed() {
    let m = manifest_with_resources(&[("known", true, 0, &[])]);
    assert_eq!(
        ResourceAwareDerivation
            .derive(&m, "never_heard_of_it")
            .right,
        coarse_write()
    );
}

#[test]
fn resource_aware_never_produces_a_grant_conservative_would_deny() {
    // The swap-in guarantee in miniature: for every shape this file
    // exercises, ResourceAwareDerivation's grant is never *more* permissive
    // than ConservativeDerivation's -- only ever equal or narrower. A guard
    // built from either derivation can only get stricter, never looser,
    // when the resource-aware one is substituted in.
    let cases: &[FuncFixture] = &[
        ("noop", true, 0, &[]),
        ("peek", true, 1, &[("db:users", AccessMode::Read)]),
        ("bump", true, 2, &[("db:users", AccessMode::Write)]),
        ("mystery", true, 1, &[]),
        ("bad", false, 1, &[("db:users", AccessMode::Read)]),
    ];
    let m = manifest_with_resources(cases);
    for (name, ..) in cases {
        let conservative = ConservativeDerivation.derive(&m, name).right;
        let aware = ResourceAwareDerivation.derive(&m, name).right;
        let narrower_or_equal = match (&conservative, &aware) {
            (a, b) if a == b => true,
            (WritRight::Write { resource_class }, _) if resource_class == "*" => true,
            _ => false,
        };
        assert!(
            narrower_or_equal,
            "{name}: resource-aware grant {aware:?} is more permissive than \
             conservative grant {conservative:?}"
        );
    }
}
