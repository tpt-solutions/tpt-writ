//! The MCP right vocabulary and the conservative proof→grant derivation.
//!
//! This crate knows proofs and rights, and nothing about MCP: it consumes the
//! [`ProofManifest`] produced by `tpt_telos_sdk::compile` and answers one
//! question per function — *what may this proved function do?*
//!
//! The pipeline position is VALIDATE → DERIVE:
//!
//! 1. **VALIDATE** — [`validate::validate_manifest_integrity`] re-derives the
//!    manifest hash via `tpt_telos_codegen::proof`'s own anti-tamper logic
//!    (the same mechanism nexus's validator wraps, used directly here as a
//!    library — no `tpt-nexus-*` dependency by explicit non-goal).
//! 2. **DERIVE** — a [`RightDerivation`] impl turns each per-function proof
//!    record into a [`WritGrant`] in the MCP vocabulary ([`WritRight`]).
//!
//! ## The v0.1 posture: fail closed
//!
//! [`ConservativeDerivation`] applies the narrowest rule that cannot
//! over-grant, with no dependency on resource-class tracking at all:
//!
//! - A function whose accepted proof carries **zero** conclusions — nothing
//!   was claimed about its effect, so nothing is granted beyond inert
//!   computation — derives `WritRight::Pure`.
//! - **Everything else** falls back to `Write { resource_class: "*" }`.
//!   Coarse in *scope*, restrictive in *meaning*: it is only ever minted
//!   because the proof could not argue the function down from it.
//!
//! ## Phase 4: `ResourceAwareDerivation`
//!
//! `tpt-telos-ir` now surfaces which `@resource(class = "...")`-tagged state
//! a function's body touches, and whether it reads or writes it (see
//! `tpt_telos_ir::VerificationProblem::resource_accesses`, carried into this
//! crate's `ProofManifest` via `tpt-telos-codegen`). [`ResourceAwareDerivation`]
//! consumes that to narrow single-resource-class functions to `Read{class}`/
//! `Write{class}` instead of the coarse fallback, while still failing closed
//! to `Write{"*"}` for untagged or multi-class functions. The
//! [`RightDerivation`] trait boundary exists precisely so this swap costs
//! nothing in `tpt-writ-mcp`/`tpt-writ-cli` — see their test suites for a
//! guard/CLI run built against each derivation from the same manifest.

use std::collections::BTreeMap;
use std::time::SystemTime;

pub mod error;
pub mod validate;

pub use error::WritError;
// The manifest type travels with the validation logic so consumers of this
// crate do not need to depend on telos-codegen directly.
pub use tpt_telos_codegen::proof::ProofManifest;
// Re-exported so `ResourceAwareDerivation` consumers (tpt-writ-mcp,
// tpt-writ-cli) don't need their own direct dependency on tpt-telos-ir just
// to name the access-mode type carried in a `FuncProof`.
pub use tpt_telos_ir::AccessMode;
pub use validate::{
    manifest_hash_bytes, parse_manifest_json, try_manifest_hash_bytes, validate_manifest,
};

// ---------------------------------------------------------------------------
// Right vocabulary
// ---------------------------------------------------------------------------

/// A right in the MCP vocabulary.
///
/// Deliberately narrow for v0.1 (spec §1): MCP tool calls are heterogeneous —
/// a tool might read a file, call an API, write a database, spawn a process —
/// so a page-style `Read`/`ReadWrite` pair does not fit. Each resource-class
/// variant names the string a `.telos` author will declare via a future
/// `@resource(...)` annotation (e.g. `"filesystem:/data"`, `"db:users"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritRight {
    /// Proved to only read the named resource class.
    Read {
        /// The declared resource class, e.g. `"filesystem:/data"`.
        resource_class: String,
    },
    /// Proved to write the named resource class.
    Write {
        /// The declared resource class, e.g. `"db:users"`.
        resource_class: String,
    },
    /// No proved resource interaction (pure computation).
    Pure,
}

impl std::fmt::Display for WritRight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WritRight::Read { resource_class } => write!(f, "Read({resource_class})"),
            WritRight::Write { resource_class } => write!(f, "Write({resource_class})"),
            WritRight::Pure => write!(f, "Pure"),
        }
    }
}

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

/// One derived capability: *this function*, holding *this right*, tied to
/// *this attested proof*.
#[derive(Debug, Clone)]
pub struct WritGrant {
    /// The `.telos` function (== MCP tool) the grant names.
    pub function_name: String,
    /// The derived right.
    pub right: WritRight,
    /// SHA-256 of the attested manifest the grant was derived from — ties the
    /// grant to a specific proof, so a stale grant is detectable against a
    /// re-issued manifest.
    pub manifest_hash: [u8; 32],
    /// When the grant was derived.
    pub issued_at: SystemTime,
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// Turns a per-function proof record into a [`WritGrant`].
///
/// A trait from day one (spec §2) so the v0.1 [`ConservativeDerivation`] and
/// the future `ResourceAwareDerivation` are swappable without touching
/// `tpt-writ-mcp` at all.
pub trait RightDerivation {
    /// Derive the grant for `function` from `manifest`.
    ///
    /// Implementations must be **fail-closed**: when in doubt, derive the
    /// most restrictive right, never a more permissive one.
    fn derive(&self, manifest: &ProofManifest, function: &str) -> WritGrant;
}

/// The v0.1 derivation: conservative, coarse, fail-closed.
///
/// See the crate-level docs for the exact rule and why it is shaped this way.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConservativeDerivation;

impl RightDerivation for ConservativeDerivation {
    fn derive(&self, manifest: &ProofManifest, function: &str) -> WritGrant {
        let right = match manifest.functions.get(function) {
            // Vacuous-proof functions (verified, zero conclusions): nothing
            // was proved about their effect, so nothing is granted beyond
            // inert computation.
            Some(proof) if proof.verified && proof.conclusions_checked == 0 => WritRight::Pure,
            // Everything else — proved obligations, unverified functions,
            // functions we have never heard of — fails closed to the single
            // coarse right.
            _ => WritRight::Write {
                resource_class: "*".to_string(),
            },
        };

        WritGrant {
            function_name: function.to_string(),
            right,
            manifest_hash: manifest_hash_bytes(manifest),
            issued_at: SystemTime::now(),
        }
    }
}

/// The Phase 4 derivation: narrows `ConservativeDerivation`'s coarse fallback
/// using the resource-class provenance `tpt-telos-ir` now surfaces (see
/// [`tpt_telos_ir::VerificationProblem::resource_accesses`]) — a static fact
/// about which `@resource(class = "...")`-tagged state a function's body
/// touches, and whether it reads or writes it.
///
/// Still fail-closed, same as [`ConservativeDerivation`]: this can only ever
/// *narrow* a grant below `Write { resource_class: "*" }`, never widen it.
/// The v0.1 right vocabulary ([`WritRight`]) has no way to name "this class
/// AND that class", so a function touching more than one tagged resource
/// class falls back to the coarse right exactly like an untagged one —
/// narrowing that further is future work (see `todo.md` Phase 4's "extended
/// `writ diff`" note), not a gap in this derivation.
///
/// | proof shape                                            | derived right       |
/// |---------------------------------------------------------|---------------------|
/// | verified, zero conclusions (vacuous)                     | `Pure`              |
/// | verified, exactly one resource class, only `Read`        | `Read { class }`    |
/// | verified, exactly one resource class, any `Write`        | `Write { class }`   |
/// | verified, zero resource classes (untagged state, if any) | `Write { "*" }`     |
/// | verified, more than one resource class                   | `Write { "*" }`     |
/// | unverified, or function absent from the manifest         | `Write { "*" }`     |
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceAwareDerivation;

impl RightDerivation for ResourceAwareDerivation {
    fn derive(&self, manifest: &ProofManifest, function: &str) -> WritGrant {
        let coarse_write = || WritRight::Write {
            resource_class: "*".to_string(),
        };

        let right = match manifest.functions.get(function) {
            Some(proof) if proof.verified && proof.conclusions_checked == 0 => WritRight::Pure,
            Some(proof) if proof.verified => match proof.resource_accesses.as_slice() {
                [(class, AccessMode::Read)] => WritRight::Read {
                    resource_class: class.clone(),
                },
                [(class, AccessMode::Write)] => WritRight::Write {
                    resource_class: class.clone(),
                },
                _ => coarse_write(),
            },
            _ => coarse_write(),
        };

        WritGrant {
            function_name: function.to_string(),
            right,
            manifest_hash: manifest_hash_bytes(manifest),
            issued_at: SystemTime::now(),
        }
    }
}

/// Convenience: derive grants for every verified function in the manifest.
///
/// Unverified functions are skipped — a failed proof earns no grant. Callers
/// that want a specific function's grant regardless of verification status
/// call [`RightDerivation::derive`] directly.
pub fn derive_all<D: RightDerivation>(
    derivation: &D,
    manifest: &ProofManifest,
) -> BTreeMap<String, WritGrant> {
    manifest
        .functions
        .iter()
        .filter(|(_, proof)| proof.verified)
        .map(|(name, _)| (name.clone(), derivation.derive(manifest, name)))
        .collect()
}

#[cfg(test)]
mod tests;
