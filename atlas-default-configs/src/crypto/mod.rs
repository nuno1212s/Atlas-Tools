use std::fs::File;
use std::io::{BufReader, Read};
use std::iter;

use anyhow::Result;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{Item, read_one};

use atlas_common::crypto::signature::{KeyPair, PublicKey};
use atlas_common::node_id::{NodeId, NodeType};

pub fn read_own_keypair(node: &NodeId) -> Result<KeyPair> {
    let file_location = format!("./ca-root/{}/private", node.0);

    let mut file_content = Vec::new();

    let _read_bytes = open_file(file_location.as_str())
        .read_to_end(&mut file_content)?;

    KeyPair::from_pkcs8(&file_content)
}

pub fn read_pk_of(node: &NodeId) -> Result<PublicKey> {
    let file_location = format!("./ca-root/{}/public", node.0);

    let mut file_content = Vec::new();

    let _read_bytes = open_file(file_location.as_str())
        .read_to_end(&mut file_content)?;

    let key_pair = KeyPair::from_pkcs8(&file_content)?;

    Ok(PublicKey::from(key_pair.public_key()))
}

fn read_certificates_from_file(mut file: &mut BufReader<File>) -> Vec<CertificateDer<'static>> {
    let mut certs = Vec::new();

    for item in iter::from_fn(|| read_one(&mut file).transpose()) {
        match item.unwrap() {
            Item::X509Certificate(cert) => {
                certs.push(cert);
            }
            _ => {
                panic!("Key given in place of a certificate")
            }
        }
    }

    certs
}

#[inline]
fn read_private_keys_from_file(mut file: BufReader<File>) -> Vec<PrivateKeyDer<'static>> {
    let mut certs = Vec::new();

    for item in iter::from_fn(|| read_one(&mut file).transpose()) {
        match item.unwrap() {
            Item::Pkcs1Key(rsa) => certs.push(PrivateKeyDer::Pkcs1(rsa)),
            Item::Pkcs8Key(rsa) => certs.push(PrivateKeyDer::Pkcs8(rsa)),
            Item::Sec1Key(rsa) => certs.push(PrivateKeyDer::Sec1(rsa)),
            _ => {
                panic!("Certificate given in place of a key")
            }
        }
    }

    certs
}

#[inline]
fn read_private_key_from_file(mut file: BufReader<File>) -> PrivateKeyDer<'static> {
    read_private_keys_from_file(file).pop().unwrap()
}

pub fn get_tls_sync_server_config(id: NodeId) -> ServerConfig {
    let id = usize::from(id);
    let mut root_store = RootCertStore::empty();

    // read ca file
    let cert = {
        let mut file = open_file("./ca-root/crt");

        let certs = read_certificates_from_file(&mut file);

        root_store
            .add(certs[0].clone())
            .expect("Failed to put root store");

        certs
    };

    // configure our cert chain and secret key
    let sk = {
        let file = open_file(format!("./ca-root/{}/private", id).as_str());

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = open_file(format!("./ca-root/{}/public", id).as_str());

        let mut certs = read_certificates_from_file(&mut file);

        certs.extend(cert);
        certs
    };

    // create server conf
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, sk)
        .expect("Failed to make server config for TLS");

    cfg
}

pub fn get_server_config_replica(id: NodeId) -> rustls::ServerConfig {
    let id = usize::from(id);
    let mut root_store = RootCertStore::empty();

    // read ca file
    let certs = {
        let mut file = open_file("./ca-root/cert");

        read_certificates_from_file(&mut file)
    };

    root_store.add(certs[0].clone()).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let mut file = open_file(&format!("./ca-root/{}/private", id));

        read_private_key_from_file(file)
    };
    let chain = {
        let mut file = open_file(&format!("./ca-root/{}/cert", id));

        let mut c = read_certificates_from_file(&mut file);

        c.extend(certs);

        c
    };

    // create server conf
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, sk)
        .expect("Failed to make cfg");

    cfg
}

pub fn get_client_config(id: NodeId) -> ClientConfig {
    let id = usize::from(id);

    let mut root_store = RootCertStore::empty();

    // configure ca file
    let certs = {
        let mut file = open_file("./ca-root/cert");
        
        read_certificates_from_file(&mut file)
    };

    root_store.add(certs[0].clone()).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let mut file = open_file(&format!("./ca-root/{}/private", id));

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = open_file(&format!("./ca-root/{}/cert", id));
        let mut c = read_certificates_from_file(&mut file);

        c.extend(certs);
        c
    };

    let cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(chain, sk)
        .expect("bad cert/key");

    cfg
}

pub fn get_client_config_replica(id: NodeId) -> rustls::ClientConfig {
    let id = usize::from(id);

    let mut root_store = RootCertStore::empty();

    // configure ca file
    let certs = {
        let mut file = open_file("./ca-root/cert");
        read_certificates_from_file(&mut file)
    };

    root_store.add(certs[0].clone()).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let mut file = open_file(&format!("./ca-root/{}/private", id));

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = open_file(&format!("./ca-root/{}/cert", id));
        let mut c = read_certificates_from_file(&mut file);

        c.extend(certs);
        c
    };

    let cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(chain, sk)
        .expect("bad cert/key");

    cfg
}

fn open_file(path: &str) -> BufReader<File> {
    let file = File::open(path).expect(path);
    BufReader::new(file)
}
