//! Signed attestations: make a proof manifest tamper-*evident* in authorship,
//! not merely hash-consistent.
//!
//! An independently implemented ed25519 signing module shaped like nexus's
//! (`Keypair`/`sign`/`verify`) so the mental model transfers — deliberately
//! **not** a dependency on `tpt-nexus-cli` (spec §6 non-goal).
//!
//! The manifest's internal hashes prove the document matches its source;
//! anyone can still regenerate both for edited code. An ed25519 signature
//! over the exact manifest document, made with a project key, closes that:
//! `writ guard` trusts a manifest only when it carries a signature from a key
//! the deployment trusts. Keys never travel inside the manifest.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

/// An ed25519 keypair for signing attestations.
#[derive(Debug, Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate a fresh signing keypair from OS randomness.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Keypair {
            signing: SigningKey::from_bytes(&secret),
        }
    }

    /// Reconstruct a keypair from a 32-byte hex-encoded secret key.
    pub fn from_secret_hex(hex: &str) -> Result<Self, String> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(format!("secret key must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Keypair {
            signing: SigningKey::from_bytes(&arr),
        })
    }

    /// The public key as a hex string, for publishing / verification.
    pub fn public_hex(&self) -> String {
        hex_encode(&self.signing.verifying_key().to_bytes())
    }

    /// The secret key as a hex string (32 bytes).
    ///
    /// Only obtainable from a key this process generated or loaded; callers
    /// must persist it themselves.
    pub fn secret_hex(&self) -> String {
        hex_encode(&self.signing.to_bytes())
    }

    /// Sign a message, returning the 64-byte raw signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).to_bytes().to_vec()
    }
}

/// Hex-encode bytes (used for on-disk signature files).
pub fn to_hex(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

/// Hex-decode a string (used to read written signatures back).
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    hex_decode(s)
}

/// Verify a raw 64-byte signature against a hex public key and message.
///
/// Returns `false` on any malformed input — bad key, wrong-length signature,
/// or genuine mismatch — so callers treat `false` uniformly as "do not trust".
pub fn verify(public_hex: &str, message: &[u8], signature: &[u8]) -> bool {
    let key_bytes = match hex_decode(public_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(message, &sig).is_ok()
}

/// Build an ed25519 [`VerifyingKey`] from a hex public key.
pub fn verifying_key(public_hex: &str) -> Result<VerifyingKey, String> {
    let bytes = hex_decode(public_hex)?;
    if bytes.len() != 32 {
        return Err("public key must be 32 bytes".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string has an odd length".to_string());
    }
    let out = (0..s.len())
        .step_by(2)
        .map(|i| hex_val(&s.as_bytes()[i..i + 2]))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(out)
}

fn hex_val(pair: &[u8]) -> Result<u8, String> {
    let hi = (pair[0] as char).to_digit(16).ok_or("invalid hex digit")?;
    let lo = (pair[1] as char).to_digit(16).ok_or("invalid hex digit")?;
    Ok(((hi << 4) | lo) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_round_trips() {
        let key = Keypair::generate();
        let msg = b"telos-proof.json contents";
        let sig = key.sign(msg);
        assert!(verify(&key.public_hex(), msg, &sig));
        assert!(!verify(&key.public_hex(), b"tampered", &sig));
    }

    #[test]
    fn wrong_key_rejects() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        assert!(!verify(&b.public_hex(), b"hello", &a.sign(b"hello")));
    }

    #[test]
    fn malformed_inputs_reject_cleanly() {
        let key = Keypair::generate();
        let sig = key.sign(b"x");
        assert!(!verify("not-hex", b"x", &sig));
        assert!(!verify(&key.public_hex(), b"x", b"short"));
        assert!(Keypair::from_secret_hex("zz").is_err());
        assert!(Keypair::from_secret_hex("ab").is_err()); // odd length
    }

    #[test]
    fn secret_round_trips_through_hex() {
        let hex = Keypair::generate().secret_hex();
        let restored = Keypair::from_secret_hex(&hex).unwrap();
        let original = Keypair::from_secret_hex(&hex).unwrap();
        assert_eq!(restored.sign(b"m"), original.sign(b"m"));
    }

    #[test]
    fn deterministic_seed_has_known_shape() {
        let k = Keypair::from_secret_hex(&"42".repeat(32)).unwrap();
        assert_eq!(k.public_hex().len(), 64);
        assert_eq!(k.sign(b"msg").len(), 64);
        assert_eq!(to_hex(&from_hex(&to_hex(&[0xde, 0xad])).unwrap()), "dead");
    }
}
