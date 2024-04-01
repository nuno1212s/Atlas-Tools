use clap::{Args, Parser, Subcommand, ValueEnum};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use std::path::Path;

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum ECDSACurve {
    #[value()]
    P256,
    #[value()]
    P384,
}

pub(crate) fn generate_ecdsa(
    private_key_dest: &Path,
    public_key_dest: &Path,
    kind: &ECDSACurve,
) -> anyhow::Result<()> {
    let random = SystemRandom::new();

    let algorithm = match kind {
        ECDSACurve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
        ECDSACurve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
    };

    let private_key_bin = EcdsaKeyPair::generate_pkcs8(algorithm, &random)?;
    let private_key = EcdsaKeyPair::from_pkcs8(algorithm, private_key_bin.as_ref(), &random)?;

    let public_key = private_key.public_key();

    std::fs::write(private_key_dest, &private_key_bin)?;
    std::fs::write(public_key_dest, public_key)?;

    let _verify: EcdsaKeyPair = EcdsaKeyPair::from_pkcs8(
        algorithm,
        &std::fs::read(private_key_dest).unwrap(),
        &random,
    )
    .expect("verify");

    Ok(())
}
