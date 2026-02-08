
pub fn gen() -> (Vec<u8>, Vec<u8>) {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let vk: VerifyingKey = (&sk).into();
    (sk.to_bytes().to_vec(), vk.to_bytes().to_vec())
}
