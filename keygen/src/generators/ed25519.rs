use openssl::pkey::PKey;

pub(crate) fn generate_ed25519() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let private_key_bin = PKey::generate_ed25519()?;

    let pkcs8_private_key = private_key_bin.private_key_to_pkcs8()?;
    let pkcs8_public_key = private_key_bin.public_key_to_pem()?;
    
    Ok((pkcs8_private_key,pkcs8_public_key,))
}
