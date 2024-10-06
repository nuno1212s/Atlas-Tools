use std::fmt::{Debug, Display};
use std::fs::File;
use std::io::{BufReader, Read};
use std::iter;

use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{read_one, Item};

use atlas_common::crypto::signature::{KeyPair, PublicKey};
use atlas_common::node_id::NodeId;

pub fn read_own_keypair<T>(node: &NodeId) -> Result<KeyPair>
where
    T: PathConstructor,
{
    let file_location = T::build_path_for(FileType::PrivateKey, Some(*node));

    let mut file_content = Vec::new();

    let _read_bytes = open_file(file_location.as_str()).read_to_end(&mut file_content)?;

    KeyPair::from_pkcs8(&file_content)
}

pub fn read_pk_of<T>(node: &NodeId) -> Result<PublicKey>
where
    T: PathConstructor,
{
    let file_location = T::build_path_for(FileType::PrivateKey, Some(*node));

    let mut file_content = Vec::new();

    let _read_bytes = open_file(file_location.as_str()).read_to_end(&mut file_content)?;

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
fn read_private_key_from_file(file: BufReader<File>) -> PrivateKeyDer<'static> {
    read_private_keys_from_file(file).pop().unwrap()
}

enum FileType {
    Cert,
    PrivateKey,
    PrivateKeyPem,
    PublicKey,
    PublicKeyPkcs,
}

pub trait PathConstructor: 'static {
    fn build_path_for(file_type: FileType, node_id: Option<NodeId>) -> String;
}

pub struct FolderPathConstructor;

pub struct FlattenedPathConstructor;

impl PathConstructor for FolderPathConstructor {
    fn build_path_for(file_type: FileType, node_id: Option<NodeId>) -> String {
        if let Some(node_id) = node_id {
            format!("./ca-root/{}/{}", node_id.0, file_type)
        } else {
            format!("./ca-root/{}", file_type)
        }
    }
}

impl PathConstructor for FlattenedPathConstructor {
    fn build_path_for(file_type: FileType, node_id: Option<NodeId>) -> String {
        if let Some(node_id) = node_id {
            format!("./ca-root/ca-root-{}-{}", node_id.0, file_type)
        } else {
            format!("./ca-root/ca-root-{}", file_type)
        }
    }
}

pub fn get_tls_sync_server_config<T>(id: NodeId) -> ServerConfig
where
    T: PathConstructor,
{
    let mut root_store = RootCertStore::empty();

    // read ca file
    let cert = {
        let mut file = open_file(T::build_path_for(FileType::Cert, None).as_str());

        let certs = read_certificates_from_file(&mut file);

        root_store
            .add(certs[0].clone())
            .expect("Failed to put root store");

        certs
    };

    // configure our cert chain and secret key
    let sk = {
        let file = open_file(T::build_path_for(FileType::PrivateKeyPem, Some(id)).as_str());

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = open_file(T::build_path_for(FileType::Cert, Some(id)).as_str());

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

pub fn get_server_config_replica<T>(id: NodeId) -> rustls::ServerConfig
where
    T: PathConstructor,
{
    let mut root_store = RootCertStore::empty();

    // read ca file
    let certs = {
        let mut file = open_file(T::build_path_for(FileType::Cert, None).as_str());

        read_certificates_from_file(&mut file)
    };

    root_store.add(certs[0].clone()).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let file = open_file(T::build_path_for(FileType::PrivateKeyPem, Some(id)).as_str());

        read_private_key_from_file(file)
    };
    let chain = {
        let mut file = open_file(T::build_path_for(FileType::Cert, Some(id)).as_str());

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

pub fn get_client_config<T>(id: NodeId) -> ClientConfig
where
    T: PathConstructor,
{
    let mut root_store = RootCertStore::empty();

    // configure ca file
    let certs = {
        let mut file = open_file(T::build_path_for(FileType::Cert, None).as_str());

        read_certificates_from_file(&mut file)
    };

    root_store.add(certs[0].clone()).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let file = open_file(T::build_path_for(FileType::PrivateKeyPem, Some(id)).as_str());

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = open_file(T::build_path_for(FileType::Cert, Some(id)).as_str());
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

pub fn get_client_config_replica<T>(id: NodeId) -> rustls::ClientConfig
where
    T: PathConstructor,
{
    let mut root_store = RootCertStore::empty();

    // configure ca file
    let certs = {
        let mut file = open_file(T::build_path_for(FileType::Cert, None).as_str());
        read_certificates_from_file(&mut file)
    };

    root_store.add(certs[0].clone()).unwrap();

    // configure our cert chain and secret key
    let sk = {
        let file = open_file(T::build_path_for(FileType::PrivateKeyPem, Some(id)).as_str());

        read_private_key_from_file(file)
    };

    let chain = {
        let mut file = open_file(T::build_path_for(FileType::Cert, Some(id)).as_str());
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

impl Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileType::Cert => write!(f, "cert"),
            FileType::PrivateKey => write!(f, "private"),
            FileType::PrivateKeyPem => write!(f, "private_pem"),
            FileType::PublicKey => write!(f, "public"),
            FileType::PublicKeyPkcs => write!(f, "public_pkcs"),
        }
    }
}

impl Debug for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}
