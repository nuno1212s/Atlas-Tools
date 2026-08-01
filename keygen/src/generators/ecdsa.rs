use clap::ValueEnum;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
};

use crate::GeneratedKeyPair;

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum ECDSACurve {
    #[value()]
    P256,
    #[value()]
    P384,
}

pub(crate) fn generate_ecdsa(kind: &ECDSACurve) -> anyhow::Result<GeneratedKeyPair> {
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

    Ok(GeneratedKeyPair {
        private_key_pkcs8: private_key_bin.as_ref().to_vec(),
        private_key_pem: vec![],
        public_key: public_key.as_ref().to_vec(),
        pub_key_pcks: public_key.as_ref().to_vec(),
    })
}
