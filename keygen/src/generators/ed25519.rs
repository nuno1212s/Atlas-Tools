use crate::GeneratedKeyPair;
use openssl::pkey::PKey;

pub(crate) fn generate_ed25519() -> anyhow::Result<GeneratedKeyPair> {
    let private_key_bin = PKey::generate_ed25519()?;

    let pkcs8_private_key = private_key_bin.private_key_to_pkcs8()?;
    let pem_private_key = private_key_bin.private_key_to_pem_pkcs8()?;
    let pkcs8_public_key = private_key_bin.public_key_to_pem()?;

    Ok(GeneratedKeyPair {
        private_key_pkcs8: pkcs8_private_key,
        private_key_pem: pem_private_key,
        public_key: pkcs8_public_key,
    })
}
