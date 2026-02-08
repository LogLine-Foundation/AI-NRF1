
// crates/envelope/src/lib.rs
//! Encrypted envelope for LogLine tuples (JSON✯Atomic or NRF bytes).
//! Uses X25519 key agreement + HKDF-SHA256 to derive a symmetric key,
//! and XChaCha20-Poly1305 for AEAD. Associated Data binds the tuple CID.

use chacha20poly1305::{aead::{Aead, KeyInit, OsRng, AeadCore}, XChaCha20Poly1305, Key, XNonce};
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct Keypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::new(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

pub struct Envelope;

impl Envelope {
    /// Encrypts `plaintext` (tuple bytes) to recipient public key. `cid_bytes` are used as AAD.
    pub fn seal(recipient_pk: &PublicKey, plaintext: &[u8], cid_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        // ephemeral key
        let eph = Keypair::generate();
        let shared = eph.secret.diffie_hellman(recipient_pk);
        // derive symmetric key
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key_bytes = [0u8; 32];
        hk.expand(b"ainrf1-envelopes", &mut key_bytes)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        // serialize header: 32B eph pub + 24B nonce
        let mut out = Vec::with_capacity(32 + 24 + plaintext.len() + 16);
        out.extend_from_slice(eph.public.as_bytes());
        out.extend_from_slice(&nonce);
        // seal
        let mut ct = cipher.encrypt(XNonce::from_slice(&nonce), chacha20poly1305::aead::Payload{ msg: plaintext, aad: cid_bytes })?;
        out.append(&mut ct);
        Ok(out)
    }

    /// Decrypts envelope using recipient secret key + CID bytes as AAD.
    pub fn open(recipient_sk: &StaticSecret, envelope: &[u8], cid_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        if envelope.len() < 32+24+16 { anyhow::bail!("short envelope"); }
        let eph_pub = PublicKey::from(<[u8;32]>::try_from(&envelope[0..32]).unwrap());
        let nonce: [u8;24] = envelope[32..56].try_into().unwrap();
        let ct = &envelope[56..];
        let shared = recipient_sk.diffie_hellman(&eph_pub);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key_bytes = [0u8; 32];
        hk.expand(b"ainrf1-envelopes", &mut key_bytes)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let pt = cipher.decrypt(XNonce::from_slice(&nonce), chacha20poly1305::aead::Payload{ msg: ct, aad: cid_bytes })?;
        Ok(pt)
    }
}
