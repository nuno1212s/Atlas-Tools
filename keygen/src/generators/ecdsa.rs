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

pub(crate) fn generate_ecdsa(kind: &ECDSACurve) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let random = SystemRandom::new();

    let algorithm = match kind {
        ECDSACurve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
        ECDSACurve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
    };

    let private_key_bin =
        EcdsaKeyPair::generate_pkcs8(algorithm, &random).expect("Failed to generate key pair");
    let private_key = EcdsaKeyPair::from_pkcs8(algorithm, private_key_bin.as_ref(), &random)
        .expect("Failed to parse the key pair");

    let public_key = private_key.public_key();

    Ok((
        private_key_bin.as_ref().to_vec(),
        public_key.as_ref().to_vec(),
    ))
}
