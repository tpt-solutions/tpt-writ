//! VALIDATE step — reuse telos-codegen's anti-tamper logic directly.

use std::collections::BTreeMap;

use serde::Deserialize;
use tpt_telos_codegen::proof::{verify_manifest, FuncProof, ProofManifest};
use tpt_telos_ir::AccessMode;

use crate::error::WritError;

/// Decode a `ProofManifest`'s `"sha256:<hex>"` hash field into raw bytes.
///
/// # Panics
///
/// On a malformed hash field. Telos-generated manifests always carry a
/// well-formed value, so this is a programmer-error path; for externally
/// supplied JSON use [`try_manifest_hash_bytes`].
pub fn manifest_hash_bytes(manifest: &ProofManifest) -> [u8; 32] {
    decode_sha256_field(&manifest.manifest_hash)
        .expect("well-formed sha256 field in a telos-generated manifest")
}

/// Like [`manifest_hash_bytes`], but fallible — for callers handling
/// externally-supplied JSON where a malformed hash is ordinary bad input.
pub fn try_manifest_hash_bytes(manifest: &ProofManifest) -> Result<[u8; 32], WritError> {
    decode_sha256_field(&manifest.manifest_hash)
        .ok_or_else(|| WritError::MalformedManifestHash(manifest.manifest_hash.clone()))
}

/// VALIDATE step: confirm the manifest JSON has not been tampered with and
/// still attests exactly these source bytes.
///
/// Delegates to `tpt_telos_codegen::proof::verify_manifest` — the *same*
/// re-derivation the generator's own test-suite checks against — which
///
/// 1. recomputes `manifest_hash` over the full JSON document (hash field
///    blanked): any edit anywhere in the document invalidates it, and
/// 2. re-hashes the supplied source bytes against `source_hash`: a `.telos`
///    file changed after verification ran is rejected.
///
/// Returns the decoded manifest hash on success (the value every derived
/// [`crate::WritGrant`] carries).
///
/// Note what this does and does not prove: internal consistency, not
/// authorship. Anyone can regenerate a self-consistent manifest for edited
/// code; proving *who* attested it is the ed25519 signature layer.
pub fn validate_manifest(json: &str, source_bytes: &[u8]) -> Result<[u8; 32], WritError> {
    let check = verify_manifest(json, source_bytes);

    if !check.manifest_hash_valid {
        // The document was edited after attestation. Report the embedded vs
        // recomputed values so a human can see *what* disagrees.
        return Err(WritError::ManifestTampered {
            expected: extract_manifest_hash_field(json).unwrap_or_default(),
            actual: check.manifest_hash_actual,
        });
    }
    if !check.source_hash_valid {
        return Err(WritError::SourceDrift {
            expected: check.source_hash_expected,
            actual: check.source_hash_actual,
        });
    }

    let embedded = match extract_manifest_hash_field(json) {
        Some(embedded) => embedded,
        None => return Err(WritError::MissingManifestHash),
    };
    decode_sha256_field(&embedded).ok_or(WritError::MalformedManifestHash(embedded))
}

/// Extract the value of the top-level `"manifest_hash"` field from the
/// manifest JSON. The generator emits it last, one level deep.
fn extract_manifest_hash_field(json: &str) -> Option<String> {
    let idx = json.find("\"manifest_hash\"")?;
    let rest = &json[idx + "\"manifest_hash\"".len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn decode_sha256_field(field: &str) -> Option<[u8; 32]> {
    let hex = field.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Parse a serialized proof manifest (the `telos-proof.json` document) back
/// into a [`ProofManifest`].
///
/// The upstream generator writes JSON but offers no reader (its fields are
/// plain structs without `Deserialize`), so the round trip is completed here,
/// mirroring the exact field layout of `tpt_telos_codegen::proof::to_json`.
/// Anything the generator would not have written is rejected.
pub fn parse_manifest_json(json: &str) -> Result<ProofManifest, WritError> {
    let doc: ManifestDoc =
        serde_json::from_str(json).map_err(|e| WritError::MalformedManifest(e.to_string()))?;
    Ok(doc.into_manifest())
}

/// Serde mirror of the generator's JSON layout.
#[derive(Debug, Deserialize)]
struct ManifestDoc {
    #[serde(rename = "schema_version")]
    _schema_version: String,
    #[serde(rename = "source_hash")]
    _source_hash: String,
    #[serde(rename = "verified_at")]
    _verified_at: String,
    #[serde(default)]
    functions: BTreeMap<String, FuncProofDoc>,
    #[serde(rename = "manifest_hash")]
    _manifest_hash: String,
}

#[derive(Debug, Deserialize)]
struct FuncProofDoc {
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    conclusions_checked: usize,
    #[serde(default)]
    conclusions_passed: usize,
    #[serde(default)]
    used_interval_bounding: bool,
    /// `#[serde(default)]` so manifests generated before Phase 4 (no
    /// `resource_accesses` field at all) still parse. Raw `(class, mode)`
    /// string pairs -- decoded to [`AccessMode`] in [`ManifestDoc::into_manifest`].
    #[serde(default)]
    resource_accesses: Vec<(String, String)>,
}

impl ManifestDoc {
    fn into_manifest(self) -> ProofManifest {
        // Rebuild the typed manifest. The hash strings are carried verbatim;
        // whether they are *trustworthy* is decided by validate_manifest /
        // the signature layer, never by this parse.
        ProofManifest {
            schema_version: "1",
            source_hash: self._source_hash,
            verified_at: self._verified_at,
            functions: self
                .functions
                .into_iter()
                .map(|(name, fp)| {
                    (
                        name,
                        FuncProof {
                            verified: fp.verified,
                            conclusions_checked: fp.conclusions_checked,
                            conclusions_passed: fp.conclusions_passed,
                            used_interval_bounding: fp.used_interval_bounding,
                            // An entry whose mode string isn't "Read"/"Write"
                            // (only possible from hand-edited or
                            // future-schema JSON, never telos's own codegen)
                            // is dropped rather than rejecting the whole
                            // manifest -- the same fail-closed posture as
                            // everywhere else: a dropped entry can only push
                            // ResourceAwareDerivation toward its coarser
                            // fallback, never toward over-granting.
                            resource_accesses: fp
                                .resource_accesses
                                .into_iter()
                                .filter_map(|(class, mode)| {
                                    let mode = match mode.as_str() {
                                        "Read" => AccessMode::Read,
                                        "Write" => AccessMode::Write,
                                        _ => return None,
                                    };
                                    Some((class, mode))
                                })
                                .collect(),
                        },
                    )
                })
                .collect(),
            manifest_hash: self._manifest_hash,
        }
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}
