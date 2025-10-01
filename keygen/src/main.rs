use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::{X509Builder, X509NameBuilder, X509};

use crate::generators::ecdsa::ECDSACurve;
use crate::generators::rsa::{RSAHash, RSALength};

pub mod generators {
    pub mod ecdsa;
    pub mod ed25519;
    pub mod rsa;
}

struct KeyNames {
    private: String,
    private_pem: String,
    public: String,
    public_pcks: String,
    cert: String,
}

fn key_names(_base: &str, _kind: &str) -> KeyNames {
    let make: fn(&str) -> String = |vis| vis.to_string();
    KeyNames {
        private: make("private"),
        private_pem: make("private_pem"),
        public: make("public"),
        public_pcks: make("public_pcks"),
        cert: make("cert"),
    }
}

#[derive(Parser, Debug)]
#[command(
    author = "Nuno Neto", version, about = "A key generation utility to quickly generate local signed certificates for secure communication", long_about = None
)]
struct KeyGenConfig {
    #[command(flatten)]
    ranges: Ranges,
    #[arg(short, long, value_name = "OUTPUT_DIR", value_hint = clap::ValueHint::DirPath)]
    output_dir: PathBuf,
    #[arg(short, long, value_name = "WORK_THREADS", default_value_t = 2)]
    work_threads: usize,
    #[arg(short, long, value_name = "GEN_CERTS", default_value_t = true)]
    gen_certs: bool,
    #[command(subcommand)]
    generator: Generator,
}

#[derive(Debug, Args)]
#[command()]
struct Ranges {
    #[arg(short, long, value_name = "CLIENT_COUNT")]
    client_count: usize,
    #[arg(short, long, value_name = "REPLICA_COUNT")]
    replica_count: usize,
    #[arg(
        long = "first-replica-id",
        value_name = "REPLICA_START_ID",
        default_value_t = 0
    )]
    start_replica: usize,
    #[arg(
        long = "first-client-id",
        value_name = "CLIENT_START_ID",
        default_value_t = 1000
    )]
    start_client: usize,
}

#[derive(Subcommand, Debug)]
#[command()]
enum Generator {
    #[command()]
    Ecdsa {
        #[arg(short)]
        curve: ECDSACurve,
    },
    #[command()]
    Rsa {
        #[arg(long)]
        len: RSALength,
        #[arg(long)]
        hash: RSAHash,
    },
    #[command()]
    ED25519,
}

#[allow(dead_code)]
struct RootCertStore {
    root_cert: Vec<u8>,
    priv_key: Vec<u8>,
    pub_key: Vec<u8>,
}

fn main() {
    let config = KeyGenConfig::parse();

    if config.output_dir.exists() && !config.output_dir.is_dir() {
        eprintln!(
            "out-dir '{}' is not a directory. Please create it or pass an existing directory.",
            config.output_dir.display()
        );

        return;
    }

    let (root_cert, priv_key, pub_key) = generate_root(&config, config.output_dir.clone());

    let root_store = RootCertStore {
        root_cert,
        priv_key,
        pub_key,
    };

    let mut pool = scoped_threadpool::Pool::new(config.work_threads as u32);

    println!("Running script with {config:#?}");

    pool.scoped(|scope| {
        let config = &config;
        let root_store = &root_store;

        for replica_id in
            config.ranges.start_replica..config.ranges.start_replica + config.ranges.replica_count
        {
            scope.execute(move || {
                generate_keys_for(
                    config,
                    config.output_dir.join(format!("{replica_id:?}/")),
                    replica_id,
                    root_store,
                )
            });
        }

        for client_id in
            config.ranges.start_client..config.ranges.start_client + config.ranges.client_count
        {
            scope.execute(move || {
                generate_keys_for(
                    config,
                    config.output_dir.join(format!("{client_id:?}/")),
                    client_id,
                    root_store,
                )
            });
        }
    });

    println!("Generated all keys");
}

fn generate_root(config: &KeyGenConfig, output_dir: PathBuf) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    std::fs::create_dir_all(output_dir.clone()).expect("Failed to create root output");

    let KeyNames {
        private,
        cert,
        private_pem,
        public_pcks,
        ..
    } = key_names("root", "ca");

    let GeneratedKeyPair {
        private_key_pkcs8: private_key,
        private_key_pem,
        public_key: pub_key,
        pub_key_pcks,
    } = generate_keypair(config);

    let certificate = generate_x509(
        &config.generator,
        "atlas".to_string(),
        &private_key,
        &pub_key,
        None,
    )
    .expect("Failed to generate root certificate");

    std::fs::write(output_dir.join(private), &private_key).expect("Failed to write private key");
    std::fs::write(output_dir.join(private_pem), private_key_pem)
        .expect("Failed to write private key");
    std::fs::write(output_dir.join(cert), &certificate).expect("Failed to write public key");
    std::fs::write(output_dir.join(public_pcks), pub_key_pcks).expect("Failed to write public key");

    (certificate, private_key, pub_key)
}

struct GeneratedKeyPair {
    private_key_pkcs8: Vec<u8>,
    private_key_pem: Vec<u8>,
    public_key: Vec<u8>,
    pub_key_pcks: Vec<u8>,
}

fn generate_keypair(config: &KeyGenConfig) -> GeneratedKeyPair {
    match &config.generator {
        Generator::Ecdsa { curve } => {
            generators::ecdsa::generate_ecdsa(curve).expect("Failed to generate ecdsa keys")
        }
        Generator::ED25519 => generators::ed25519::generate_ed25519().expect("generate ed"),
        Generator::Rsa { len, .. } => generators::rsa::generate_rsa(len).expect("generate rsa"),
    }
}

fn generate_keys_for(
    config: &KeyGenConfig,
    output_dir: PathBuf,
    id: usize,
    root_ca: &RootCertStore,
) {
    println!(
        "Generating keys for id {} to dir {}",
        id,
        output_dir.as_path().display()
    );

    if !output_dir.is_dir() {
        std::fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    }

    let KeyNames {
        private,
        private_pem,
        public,
        public_pcks,
        cert,
    } = match &config.generator {
        Generator::Ecdsa { curve } => key_names("ecdsa", &format!("{curve:?}")),
        Generator::ED25519 => key_names("ed", "25519"),
        Generator::Rsa { len, .. } => key_names("rsa", &format!("{len:?}")),
    };

    let GeneratedKeyPair {
        private_key_pkcs8: private_key,
        public_key,
        private_key_pem,
        pub_key_pcks,
    } = generate_keypair(config);

    std::fs::write(output_dir.join(private), &private_key).expect("Failed to write private key");
    std::fs::write(output_dir.join(private_pem), private_key_pem)
        .expect("Failed to write private key");
    std::fs::write(output_dir.join(public), &public_key).expect("Failed to write public key");
    std::fs::write(output_dir.join(public_pcks), &pub_key_pcks)
        .expect("Failed to write public key");

    if config.gen_certs {
        let certificate_path = &output_dir.join(cert);

        let certificate = generate_x509(
            &config.generator,
            format!("atlas{id}"),
            &private_key,
            &public_key,
            Some(root_ca),
        )
        .expect("");

        std::fs::write(certificate_path, certificate).expect("Failed to write certificate");
    }
}

pub(crate) fn generate_x509(
    alg: &Generator,
    name: String,
    private_key: &[u8],
    public_key: &[u8],
    ca: Option<&RootCertStore>,
) -> anyhow::Result<Vec<u8>> {
    if let Some(RootCertStore {
        root_cert,
        priv_key,
        pub_key: _,
    }) = ca
    {
        let _subject_pkey = PKey::private_key_from_pkcs8(private_key)?;
        let subject_pubkey = PKey::public_key_from_pem(public_key)?;

        let root_cert = X509::from_pem(root_cert)?;
        let root_pkey = PKey::private_key_from_pkcs8(priv_key)?;

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_pubkey(&subject_pubkey)?;

        let issuer_name = root_cert.subject_name();
        builder.set_issuer_name(issuer_name)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", name.as_str())?;
        let name = name_builder.build();
        builder.set_subject_name(&name)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        match alg {
            Generator::Ecdsa { curve, .. } => match curve {
                ECDSACurve::P256 => builder.sign(&root_pkey, MessageDigest::sha3_256())?,
                ECDSACurve::P384 => builder.sign(&root_pkey, MessageDigest::sha3_384())?,
            },
            Generator::ED25519 => builder.sign(&root_pkey, MessageDigest::null())?,
            Generator::Rsa { hash, .. } => match hash {
                RSAHash::SHA256 => builder.sign(&root_pkey, MessageDigest::sha3_256())?,
                RSAHash::SHA384 => builder.sign(&root_pkey, MessageDigest::sha3_384())?,
                RSAHash::SHA512 => builder.sign(&root_pkey, MessageDigest::sha3_512())?,
            },
        };

        // Sign the certificate with the root certificate's private key
        let certificate = builder.build();

        // Convert the certificate to PEM and save it
        let cert_pem = certificate.to_pem()?;

        Ok(cert_pem)
    } else {
        // Load the existing private key
        let private_key =
            PKey::private_key_from_pkcs8(private_key).context("Failed reading the private key")?;

        // Create a new X509 certificate builder
        let mut builder = X509Builder::new()?;

        // Set the version of the certificate (X.509 Version 3)
        builder.set_version(2)?;

        // Create and set the subject name
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", "PT")?;
        name_builder.append_entry_by_text("CN", name.as_str())?;
        let name = name_builder.build();
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;

        // Set the public key
        builder.set_pubkey(&private_key)?;

        // Set the validity period
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        // Sign the certificate with the private key
        match alg {
            Generator::Ecdsa { curve, .. } => match curve {
                ECDSACurve::P256 => builder.sign(&private_key, MessageDigest::sha3_256())?,
                ECDSACurve::P384 => builder.sign(&private_key, MessageDigest::sha3_384())?,
            },
            Generator::ED25519 => builder.sign(&private_key, MessageDigest::null())?,
            Generator::Rsa { hash, .. } => match hash {
                RSAHash::SHA256 => builder.sign(&private_key, MessageDigest::sha3_256())?,
                RSAHash::SHA384 => builder.sign(&private_key, MessageDigest::sha3_384())?,
                RSAHash::SHA512 => builder.sign(&private_key, MessageDigest::sha3_512())?,
            },
        };

        // Build the certificate
        let certificate = builder.build();

        // Convert the certificate to PEM
        Ok(certificate.to_pem()?)
    }
}
