use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub(crate) fn generate_ed25519() -> anyhow::Result<(String, String)> {
    let random = SystemRandom::new();

    let private_key_bin =
        Ed25519KeyPair::generate_pkcs8(&random).expect("Failed to generate key pair");
    let private_key =
        Ed25519KeyPair::from_pkcs8(private_key_bin.as_ref()).expect("Failed to parse the key pair");

    let public_key = private_key.public_key();

    Ok((
        std::str::from_utf8(private_key_bin.as_ref())?.to_string(),
        std::str::from_utf8(public_key.as_ref())?.to_string(),
    ))
}
