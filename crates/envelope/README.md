
# envelope (Rust crate)

Encrypted envelope for LogLine tuples (JSON✯Atomic or NRF bytes).

- X25519 key agreement → HKDF-SHA256 → XChaCha20-Poly1305 (AEAD)
- AAD binds the tuple CID (`b3:...` bytes) to the ciphertext
- Header: `[ephemeral_pub(32) || nonce(24) || ciphertext(...)]`

Usage:
```rust
let kp = Keypair::generate();
let cid_bytes = hex::decode("e3...")?;
let sealed = Envelope::seal(&kp.public, tuple_bytes, &cid_bytes)?;
let opened = Envelope::open(&kp.secret, &sealed, &cid_bytes)?;
assert_eq!(tuple_bytes, opened);
```
