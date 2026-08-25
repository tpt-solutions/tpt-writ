//! Error type for `tpt-writ-core`.

/// Everything that can go wrong while validating or deriving from a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritError {
    /// The recomputed manifest hash does not match the embedded one — the
    /// JSON document was edited after attestation.
    ManifestTampered {
        /// Hash value embedded in the (edited) document.
        expected: String,
        /// Hash re-derived from the document's actual contents.
        actual: String,
    },
    /// The manifest is internally consistent but was attested for a
    /// different source file — the `.telos` changed after verification ran.
    SourceDrift {
        /// Hash of the source the manifest was attested against.
        expected: String,
        /// Hash of the source actually supplied.
        actual: String,
    },
    /// The document carries no readable top-level `manifest_hash`.
    MissingManifestHash,
    /// The `manifest_hash` field exists but is not a well-formed
    /// `sha256:<64 hex chars>` value.
    MalformedManifestHash(String),
    /// The manifest JSON could not be parsed at all.
    MalformedManifest(String),
}

impl std::fmt::Display for WritError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WritError::ManifestTampered { expected, actual } => write!(
                f,
                "manifest tampered: embedded hash {expected} != recomputed {actual}"
            ),
            WritError::SourceDrift { expected, actual } => write!(
                f,
                "source drift: manifest attested for {expected}, but source hashes to {actual}"
            ),
            WritError::MissingManifestHash => {
                write!(f, "manifest carries no \"manifest_hash\" field")
            }
            WritError::MalformedManifestHash(h) => {
                write!(f, "manifest_hash is not sha256:<64 hex>: {h}")
            }
            WritError::MalformedManifest(e) => write!(f, "manifest JSON unparseable: {e}"),
        }
    }
}

impl std::error::Error for WritError {}
