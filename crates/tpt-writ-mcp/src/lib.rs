//! The MCP interceptor: load a validated manifest, derive grants, and answer
//! exactly one question per tool call — *allowed, or denied?*
//!
//! `WritGuard` is deliberately transport-agnostic: it depends on
//! `tpt-writ-core` (proofs and rights) and on nothing MCP-shaped. It wraps an
//! `rmcp` server as a thin decorator at the dispatch entry point (see
//! `out-writ-examples`), and it sits inside `writ guard`'s stdio relay for
//! servers you cannot recompile. It never forks a server implementation.
//!
//! Denials are enriched, mirroring Archon's `CacheError::Denied` clarity:
//! [`WritDenied`] always states *what was attempted*, *what grant was held*,
//! and *why the two do not fit*.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tpt_writ_core::{
    derive_all, parse_manifest_json, try_manifest_hash_bytes, ProofManifest, RightDerivation,
    WritError, WritGrant, WritRight,
};

// ---------------------------------------------------------------------------
// Attempted access
// ---------------------------------------------------------------------------

/// What the caller is trying to do to the resource class, right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Read-only access.
    Read,
    /// Mutating access.
    Write,
}

impl std::fmt::Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessMode::Read => write!(f, "Read"),
            AccessMode::Write => write!(f, "Write"),
        }
    }
}

/// Why a call was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// No grant exists for this tool: either it is not in the attested
    /// manifest or its proof failed. Nothing was held.
    NoGrant,
    /// The tool holds `Pure` — proved free of resource interaction — so any
    /// resource access oversteps.
    PureHoldsNoResourceAccess,
    /// The held right names a different resource class.
    WrongResourceClass {
        /// The class the held right actually covers.
        held_class: String,
    },
    /// The class matches but only read access is held.
    ReadHeldForWriteAttempt {
        /// The class both sides agree on.
        resource_class: String,
    },
}

/// An enriched denial: what did you hold vs. what did you need?
///
/// Mirrors Archon's `CacheError::Denied` clarity (spec §3), independently
/// defined here — no `tpt-archon-*` dependency.
#[derive(Debug, Clone)]
pub struct WritDenied {
    /// The tool whose call was refused.
    pub tool_name: String,
    /// The access that was attempted.
    pub attempted_mode: AccessMode,
    /// The resource class the call targeted.
    pub attempted_resource_class: String,
    /// The right the tool holds, if any (`None` == no grant at all).
    pub held: Option<WritRight>,
    /// Why held and attempted do not fit.
    pub reason: DenialReason,
}

impl std::fmt::Display for WritDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let attempted = match self.attempted_mode {
            AccessMode::Read => format!("Read({})", self.attempted_resource_class),
            AccessMode::Write => format!("Write({})", self.attempted_resource_class),
        };
        match (&self.reason, &self.held) {
            (DenialReason::NoGrant, _) => write!(
                f,
                "denied `{}`: attempted {attempted}, but no grant exists for this tool \
                 (absent from the attested proof, or its proof failed)",
                self.tool_name
            ),
            (_, Some(held)) => write!(
                f,
                "denied `{}`: attempted {attempted}, but holds {held} ({})",
                self.tool_name,
                reason_text(&self.reason),
            ),
            (_, None) => write!(
                f,
                "denied `{}`: attempted {attempted} with no grant held ({})",
                self.tool_name,
                reason_text(&self.reason),
            ),
        }
    }
}

fn reason_text(reason: &DenialReason) -> &'static str {
    match reason {
        DenialReason::NoGrant => "no grant for this tool",
        DenialReason::PureHoldsNoResourceAccess => "a Pure grant covers no resource access",
        DenialReason::WrongResourceClass { .. } => "held right names a different resource class",
        DenialReason::ReadHeldForWriteAttempt { .. } => "only read access is held",
    }
}

/// Everything that can go wrong while loading a guard from externally
/// supplied material (as opposed to a denial, which is a *decision*, not a
/// malfunction).
#[derive(Debug)]
pub enum WritGuardError {
    /// The manifest failed parsing or integrity checks — tampered document,
    /// drifted source, malformed hash.
    Manifest(WritError),
    /// The ed25519 signature does not verify against the supplied key. The
    /// manifest's *provenance* is unproven: anyone could have issued it.
    InvalidSignature,
}

impl std::fmt::Display for WritGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WritGuardError::Manifest(e) => write!(f, "manifest rejected: {e}"),
            WritGuardError::InvalidSignature => {
                write!(f, "signature does not verify against the supplied key")
            }
        }
    }
}

impl std::error::Error for WritGuardError {}

/// The interceptor: holds one grant per attested function and answers
/// `check_call` before any real handler runs.
///
/// Generic over [`RightDerivation`] from day one: swapping
/// `ConservativeDerivation` for the future resource-aware derivation changes
/// nothing in this crate or its consumers.
pub struct WritGuard<D: RightDerivation> {
    derivation: D,
    grants: BTreeMap<String, WritGrant>,
    manifest_hash: [u8; 32],
}

impl<D: RightDerivation> std::fmt::Debug for WritGuard<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritGuard")
            .field("grants", &self.grants.keys().collect::<Vec<_>>())
            .field("manifest_hash", &hex_short(&self.manifest_hash))
            .finish()
    }
}

fn hex_short(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in bytes.iter().take(8) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl<D: RightDerivation> WritGuard<D> {
    /// Load an already-validated manifest and populate grants via `D::derive`.
    ///
    /// "Already-validated" means the caller ran
    /// [`tpt_writ_core::validate_manifest`] on the serialized form (or just
    /// produced the manifest from `compile`). Grants exist only for functions
    /// whose proofs **passed** — a failed proof earns nothing, so any tool
    /// name absent here is denied at [`Self::check_call`].
    pub fn from_manifest(manifest: &ProofManifest, derivation: D) -> Self {
        let grants = derive_all(&derivation, manifest);
        let manifest_hash = try_manifest_hash_bytes(manifest).expect("well-formed hash");
        Self {
            derivation,
            grants,
            manifest_hash,
        }
    }

    /// Load a guard from a serialized `telos-proof.json` document plus an
    /// ed25519 signature over those exact bytes, made with `pubkey`.
    ///
    /// Two independent gates, both required:
    ///
    /// 1. **Authorship** — the signature must verify. A manifest is
    ///    trustworthy only if it carries a signature from a key the project
    ///    trusts (the same posture as `nexus verify-signature`, implemented
    ///    independently here).
    /// 2. **Well-formedness** — the embedded hash fields must decode.
    ///
    /// Full source-hash VALIDATE (`tpt_writ_core::validate_manifest`) needs
    /// the original `.telos` bytes, which a guard deployment usually does not
    /// hold; run that first when you have them.
    pub fn from_signed_manifest(
        manifest_json: &str,
        pubkey: &VerifyingKey,
        sig: &Signature,
        derivation: D,
    ) -> Result<Self, WritGuardError> {
        if pubkey.verify(manifest_json.as_bytes(), sig).is_err() {
            return Err(WritGuardError::InvalidSignature);
        }
        let manifest = parse_manifest_json(manifest_json).map_err(WritGuardError::Manifest)?;
        try_manifest_hash_bytes(&manifest).map_err(WritGuardError::Manifest)?;
        Ok(Self::from_manifest(&manifest, derivation))
    }

    /// The grants currently enforced, keyed by tool name.
    pub fn grants(&self) -> &BTreeMap<String, WritGrant> {
        &self.grants
    }

    /// Hash of the manifest every grant was derived from.
    pub fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }

    /// The derivation strategy this guard enforces with.
    pub fn derivation(&self) -> &D {
        &self.derivation
    }

    /// Check that a tool holds **any** grant — the right question for tools
    /// whose handler performs no resource interaction (pure computation).
    ///
    /// [`Self::check_call`] answers "may this call touch this class this
    /// way?"; a `Pure` tool never touches anything, so asking it would deny
    /// by construction. This variant asks only "is this tool attested?".
    pub fn check_tool(&self, tool_name: &str) -> Result<(), WritDenied> {
        match self.grants.contains_key(tool_name) {
            true => Ok(()),
            false => Err(WritDenied {
                tool_name: tool_name.to_string(),
                attempted_mode: AccessMode::Read,
                attempted_resource_class: "<none>".to_string(),
                held: None,
                reason: DenialReason::NoGrant,
            }),
        }
    }

    /// Called before dispatching an MCP tool call: `Ok(())` passes through,
    /// `Err(WritDenied)` states what was held vs. what was attempted.
    ///
    /// Decision table (v0.1 conservative vocabulary):
    ///
    /// | held right            | attempted          | result |
    /// |-----------------------|--------------------|--------|
    /// | (none)                | anything           | deny `NoGrant` |
    /// | `Write{"*"}`          | any class, any mode| **allow** |
    /// | `Write{c}`            | class `c`, any mode| **allow** |
    /// | `Read{c}`             | read, class `c`    | **allow** |
    /// | `Pure`                | anything           | deny |
    /// | `Read{c}` / `Write{c}`| other class        | deny `WrongResourceClass` |
    /// | `Read{c}`             | write, class `c`   | deny `ReadHeldForWriteAttempt` |
    pub fn check_call(
        &self,
        tool_name: &str,
        resource_class: &str,
        mode: AccessMode,
    ) -> Result<(), WritDenied> {
        let Some(grant) = self.grants.get(tool_name) else {
            return Err(WritDenied {
                tool_name: tool_name.to_string(),
                attempted_mode: mode,
                attempted_resource_class: resource_class.to_string(),
                held: None,
                reason: DenialReason::NoGrant,
            });
        };

        let allowed = match (&grant.right, mode) {
            // The coarse fallback covers every class and every mode — it is
            // what "the proof could not narrow this function" means.
            (
                WritRight::Write {
                    resource_class: class,
                },
                _,
            ) if class == "*" => true,
            (
                WritRight::Write {
                    resource_class: class,
                },
                _,
            ) => class == resource_class,
            (
                WritRight::Read {
                    resource_class: class,
                },
                AccessMode::Read,
            ) => class == resource_class,
            _ => false,
        };
        if allowed {
            return Ok(());
        }

        let reason = match &grant.right {
            WritRight::Pure => DenialReason::PureHoldsNoResourceAccess,
            WritRight::Write {
                resource_class: class,
            }
            | WritRight::Read {
                resource_class: class,
            } if class != resource_class => DenialReason::WrongResourceClass {
                held_class: class.clone(),
            },
            WritRight::Read { .. } => DenialReason::ReadHeldForWriteAttempt {
                resource_class: resource_class.to_string(),
            },
            // Write{"*"} allows everything; reaching here is impossible.
            WritRight::Write { .. } => return Ok(()),
        };

        Err(WritDenied {
            tool_name: tool_name.to_string(),
            attempted_mode: mode,
            attempted_resource_class: resource_class.to_string(),
            held: Some(grant.right.clone()),
            reason,
        })
    }
}

#[cfg(test)]
mod tests;
