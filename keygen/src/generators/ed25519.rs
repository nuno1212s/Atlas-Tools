use anyhow::Context;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::Path;

pub(crate) fn generate_ed25519(
    private_key_dest: &Path,
    public_key_dest: &Path,
) -> anyhow::Result<()> {
    let random = SystemRandom::new();

    let private_key_bin = Ed25519KeyPair::generate_pkcs8(&random)?;
    let private_key = Ed25519KeyPair::from_pkcs8(private_key_bin.as_ref())?;

    let public_key = private_key.public_key();

    std::fs::write(private_key_dest, private_key_bin)?;
    std::fs::write(public_key_dest, public_key)?;

    let pkcs8 = &std::fs::read(private_key_dest)
        .with_context(|| format!("Failed to read file {:?}", private_key_dest))?;

    let _verify: Ed25519KeyPair =
        Ed25519KeyPair::from_pkcs8(pkcs8).context("Failed to verify key pair")?;

    Ok(())
}
