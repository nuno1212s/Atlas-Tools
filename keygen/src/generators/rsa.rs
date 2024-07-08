use clap::ValueEnum;
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use std::path::Path;

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum RSALength {
    #[value(name = "2048")]
    L2048,
    #[value(name = "4096")]
    L4096,
    #[value(name = "8192")]
    L8192,
}

impl From<&RSALength> for u32 {
    fn from(value: &RSALength) -> Self {
        match value {
            RSALength::L2048 => 2048,
            RSALength::L4096 => 4096,
            RSALength::L8192 => 8192,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum RSAHash {
    #[value()]
    SHA256,
    #[value()]
    SHA384,
    #[value()]
    SHA512,
}

pub(crate) fn generate_rsa(length: &RSALength) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let rsa = Rsa::generate(length.into())?;

    let pkey = PKey::from_rsa(rsa)?;

    let private_key = pkey.private_key_to_pem_pkcs8()?;
    let public_key = pkey.public_key_to_pem()?;

    Ok((
        private_key,
        public_key,
    ))
}
