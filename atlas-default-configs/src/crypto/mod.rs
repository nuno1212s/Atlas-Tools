use std::fs::File;
use std::io::BufReader;
use std::iter;
use std::sync::Arc;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls_pemfile::{Item, read_one};
use atlas_common::crypto::signature::{KeyPair, PublicKey};
use anyhow::Result;
use atlas_common::node_id::NodeId;

pub fn read_own_keypair(node: &NodeId) -> Result<KeyPair> {
    todo!()
}

pub fn read_pk_of(node: &NodeId) -> Result<PublicKey> {
    todo!()
}

pub fn read_certificates_from_file(mut file: &mut BufReader<File>) -> Vec<Certificate> {
    let mut certs = Vec::new();

    for item in iter::from_fn(|| read_one(&mut file).transpose()) {
        match item.unwrap() {
            Item::X509Certificate(cert) => {
                certs.push(Certificate(cert));
            }
            Item::RSAKey(_) => {
                panic!("Key given in place of a certificate")
            }
            Item::PKCS8Key(_) => {
                panic!("Key given in place of a certificate")
            }
            Item::ECKey(_) => {
                panic!("Key given in place of a certificate")
            }
            _ => {
                panic!("Key given in place of a certificate")
            }
        }
    }

    certs
}

#[inline]
pub fn read_private_keys_from_file(mut file: BufReader<File>) -> Vec<PrivateKey> {
    let mut certs = Vec::new();

    for item in iter::from_fn(|| read_one(&mut file).transpose()) {
        match item.unwrap() {
            Item::RSAKey(rsa) => {
                certs.push(PrivateKey(rsa))
            }
            Item::PKCS8Key(rsa) => {
                certs.push(PrivateKey(rsa))
            }
            Item::ECKey(rsa) => {
                certs.push(PrivateKey(rsa))
            }
            _ => {
                panic!("Key given in place of a certificate")
            }
        }
    }

    certs
}

#[inline]
pub fn read_private_key_from_file(mut file: BufReader<File>) -> PrivateKey {
    read_private_keys_from_file(file).pop().unwrap()
}

pub fn get_tls_sync_server_config(id: NodeId) -> ServerConfig {
    let id = usize::from(id);
    let mut root_store = RootCertStore::empty();

    // read ca file
    let cert = {
        let mut file = open_file("./ca-root/crt");

        let certs = read_certificates_from_file(&mut file);

        root_store.add(&certs[0]).expect("Failed to put root store");

        certs
    };

    // configure our cert chain and secret key
    let sk = {
        let mut file = if id < 1000 {
            open_file(&format!("./ca-root/srv{}/key", id))
        } else {
            open_file(&format!("./ca-root/cli{}/key", id))
        };

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = if id < 1000 {
            open_file(&format!("./ca-root/srv{}/crt", id))
        } else {
            open_file(&format!("./ca-root/cli{}/crt", id))
        };

        let mut certs = read_certificates_from_file(&mut file);

        certs.extend(cert);
        certs
    };

    // create server conf
    let auth = AllowAnyAuthenticatedClient::new(root_store);
    let cfg = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(Arc::new(auth))
        .with_single_cert(chain, sk)
        .expect("Failed to make cfg");
    cfg
}

pub fn get_server_config_replica(id: NodeId) -> rustls::ServerConfig {
    let id = usize::from(id);
    let mut root_store = RootCertStore::empty();

    // read ca file
    let certs = {
        let mut file = open_file("./ca-root/crt");

        read_certificates_from_file(&mut file)
    };

    root_store.add(&certs[0]).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let mut file = if id < 1000 {
            open_file(&format!("./ca-root/srv{}/key", id))
        } else {
            open_file(&format!("./ca-root/cli{}/key", id))
        };

        read_private_key_from_file(file)
    };
    let chain = {
        let mut file = if id < 1000 {
            open_file(&format!("./ca-root/srv{}/crt", id))
        } else {
            open_file(&format!("./ca-root/cli{}/crt", id))
        };

        let mut c = read_certificates_from_file(&mut file);

        c.extend(certs);

        c
    };

    // create server conf
    let auth = AllowAnyAuthenticatedClient::new(root_store);

    let cfg = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(Arc::new(auth))
        .with_single_cert(chain, sk)
        .expect("Failed to make cfg");

    cfg
}

pub fn get_client_config(id: NodeId) -> ClientConfig {
    let id = usize::from(id);

    let mut root_store = RootCertStore::empty();

    // configure ca file
    let certs = {
        let mut file = open_file("./ca-root/crt");
        read_certificates_from_file(&mut file)
    };

    root_store.add(&certs[0]).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let mut file = if id < 1000 {
            open_file(&format!("./ca-root/srv{}/key", id))
        } else {
            open_file(&format!("./ca-root/cli{}/key", id))
        };

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = if id < 1000 {
            open_file(&format!("./ca-root/srv{}/crt", id))
        } else {
            open_file(&format!("./ca-root/cli{}/crt", id))
        };
        let mut c = read_certificates_from_file(&mut file);

        c.extend(certs);
        c
    };

    let cfg = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_single_cert(chain, sk)
        .expect("bad cert/key");

    cfg
}

pub fn get_client_config_replica(id: NodeId) -> rustls::ClientConfig {
    let id = usize::from(id);

    let mut root_store = RootCertStore::empty();

    // configure ca file
    let certs = {
        let mut file = open_file("./ca-root/crt");
        read_certificates_from_file(&mut file)
    };

    root_store.add(&certs[0]).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let mut file = if id < 1000 {
            open_file(&format!("./ca-root/srv{}/key", id))
        } else {
            open_file(&format!("./ca-root/cli{}/key", id))
        };

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = if id < 1000 {
            open_file(&format!("./ca-root/srv{}/crt", id))
        } else {
            open_file(&format!("./ca-root/cli{}/crt", id))
        };
        let mut c = read_certificates_from_file(&mut file);

        c.extend(certs);
        c
    };

    let cfg = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_single_cert(chain, sk)
        .expect("bad cert/key");

    cfg
}


fn open_file(path: &str) -> BufReader<File> {
    let file = File::open(path).expect(path);
    BufReader::new(file)
}