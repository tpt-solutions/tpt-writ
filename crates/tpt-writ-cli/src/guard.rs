//! `writ guard` internals: load a manifest, build a guard, spawn the target,
//! and stand between it and the agent.
//!
//! Trust model (fail-closed): a manifest is accepted only when at least one
//! independent gate passes —
//!
//! - `--source <file>`: full VALIDATE (`tpt_writ_core::validate_manifest`),
//!   re-deriving both the manifest hash and the source hash; or
//! - `--pubkey <hex> --signature <sig-or-file>`: an ed25519 signature over
//!   the exact manifest document bytes.
//!
//! With neither, there is no evidence the manifest means anything, and the
//! command refuses. This differs from the spec sketch's
//! `from_manifest(manifest, sig)` — a bare signature verifies only against a
//! public key, so the key travels with it here.

use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use ed25519_dalek::{Signature as Ed25519Signature, Verifier};
use tpt_writ_core::{
    parse_manifest_json, validate_manifest, ConservativeDerivation, ProofManifest, WritError,
};
use tpt_writ_mcp::WritGuard;

/// A loaded, gate-checked manifest plus its raw JSON bytes.
pub struct LoadedManifest {
    /// Raw document bytes exactly as read (the signature's message).
    pub json: String,
    /// The parsed manifest.
    pub manifest: ProofManifest,
    /// Which gates passed (for the startup report).
    pub validated_by_source: bool,
    pub verified_signature: bool,
}

/// Errors from [`load_manifest`], each already phrased for humans.
#[derive(Debug)]
pub enum LoadError {
    /// Neither trust gate was supplied.
    NoTrustGate,
    /// The source VALIDATE failed (tamper or drift).
    Validate(WritError),
    /// The signature did not verify against the supplied key.
    BadSignature,
    /// The document could not be parsed as a telos proof manifest.
    Parse(WritError),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NoTrustGate => write!(
                f,
                "refusing to guard from an unverified manifest: pass --source \
                 (hash check) and/or --pubkey + --signature (authorship check)"
            ),
            LoadError::Validate(e) => write!(f, "manifest rejected by VALIDATE: {e}"),
            LoadError::BadSignature => {
                write!(f, "signature does not verify against --pubkey")
            }
            LoadError::Parse(e) => write!(f, "manifest unparseable: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Read the manifest file and apply whichever trust gates were requested.
///
/// `manifest_bytes` come from disk; `source_bytes` is `Some` iff `--source`
/// was given; `(pubkey_hex, sig_hex)` are `Some` iff both were given.
pub fn load_manifest(
    manifest_bytes: &[u8],
    source_bytes: Option<&[u8]>,
    pubkey_and_sig: Option<(&str, &str)>,
) -> Result<LoadedManifest, LoadError> {
    let json = std::str::from_utf8(manifest_bytes)
        .map_err(|e| LoadError::Parse(WritError::MalformedManifest(e.to_string())))?
        .to_string();

    let mut validated_by_source = false;
    if let Some(source) = source_bytes {
        validate_manifest(&json, source).map_err(LoadError::Validate)?;
        validated_by_source = true;
    }

    let mut verified_signature = false;
    if let Some((pubkey_hex, sig_hex)) = pubkey_and_sig {
        let key = super::signing::verifying_key(pubkey_hex).map_err(|_| LoadError::BadSignature)?;
        let sig = ed25519_sig_from_hex(sig_hex).ok_or(LoadError::BadSignature)?;
        if key.verify(manifest_bytes, &sig).is_err() {
            return Err(LoadError::BadSignature);
        }
        verified_signature = true;
    }

    if !validated_by_source && !verified_signature {
        return Err(LoadError::NoTrustGate);
    }

    let manifest = parse_manifest_json(&json).map_err(LoadError::Parse)?;
    Ok(LoadedManifest {
        json,
        manifest,
        validated_by_source,
        verified_signature,
    })
}

fn ed25519_sig_from_hex(hex_or_file_contents: &str) -> Option<Ed25519Signature> {
    let trimmed = hex_or_file_contents.trim();
    // Accept either a bare hex string or the contents of a `.sig` file
    // (trailing whitespace already handled by trim).
    let bytes = super::signing::from_hex(trimmed).ok()?;
    Ed25519Signature::from_slice(&bytes).ok()
}

/// Spawn the target MCP server with piped stdio.
pub fn spawn_target(program: &str, args: &[String]) -> anyhow::Result<Child> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn target `{program}`: {e}"))
}

/// Build the runtime guard from a loaded manifest.
pub fn build_guard(loaded: &LoadedManifest) -> Arc<WritGuard<ConservativeDerivation>> {
    Arc::new(WritGuard::from_manifest(
        &loaded.manifest,
        ConservativeDerivation,
    ))
}
