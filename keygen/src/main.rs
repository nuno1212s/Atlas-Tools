use crate::generators::ecdsa::ECDSACurve;
use crate::generators::rsa::{RSAHash, RSALength};
use clap::{Args, Parser, Subcommand};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use rcgen::{Certificate, CertificateParams, IsCa};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub mod generators {
    pub mod ecdsa;
    pub mod ed25519;
    pub mod rsa;
}

struct KeyNames {
    private: String,
    public: String,
    cert: String,
}

fn key_names(_base: &str, _kind: &str) -> KeyNames {
    let make = |vis| format!("{}", vis);
    KeyNames {
        private: make("private"),
        public: make("public"),
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
    RSA {
        #[arg(long)]
        len: RSALength,
        #[arg(long)]
        hash: RSAHash,
    },
    #[command()]
    ED25519,
}

struct RootCertStore {
    root_cert: String,
    priv_key: String,
    pub_key: String,
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

    println!("Running script with {:#?}", config);

    pool.scoped(|scope| {
        let config = &config;
        let root_store = &root_store;

        for replica_id in
            config.ranges.start_replica..config.ranges.start_replica + config.ranges.replica_count
        {
            scope.execute(move || {
                generate_keys_for(
                    config,
                    config.output_dir.join(format!("{:?}/", replica_id)),
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
                    config.output_dir.join(format!("{:?}/", client_id)),
                    client_id,
                    root_store,
                )
            });
        }
    });

    println!("Generated all keys");
}

fn generate_root(config: &KeyGenConfig, output_dir: PathBuf) -> (String, String, String) {
    std::fs::create_dir_all(output_dir.clone()).expect("Failed to create root output");

    let KeyNames { private, cert, .. } = key_names("root", "ca");

    let (private_key, pub_key) = generate_keypair(config);

    let certificate = generate_x509(
        &config.generator,
        "atlas".to_string(),
        &private_key,
        &pub_key,
        None,
    )
    .expect("Failed to generate root certificate");

    std::fs::write(output_dir.join(private), &private_key).expect("Failed to write private key");
    std::fs::write(output_dir.join(cert), &certificate).expect("Failed to write public key");

    (
        std::str::from_utf8(&certificate)
            .expect("Failed to read certificate")
            .to_string(),
        private_key,
        pub_key,
    )
}

fn generate_keypair(config: &KeyGenConfig) -> (String, String) {
    match &config.generator {
        Generator::Ecdsa { curve } => {
            let (private_key, public) =
                generators::ecdsa::generate_ecdsa(curve).expect("Failed to generate ecdsa keys");

            (private_key, public)
        }
        Generator::ED25519 => {
            let (private_key, public_key) =
                generators::ed25519::generate_ed25519().expect("generate ed");

            (private_key, public_key)
        }
        Generator::RSA { len, .. } => {
            let (private_key, public_key) =
                generators::rsa::generate_rsa(len).expect("generate rsa");

            (private_key, public_key)
        }
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
        public,
        cert,
    } = match &config.generator {
        Generator::Ecdsa { curve } => key_names("ecdsa", &format!("{:?}", curve)),
        Generator::ED25519 => key_names("ed", "25519"),
        Generator::RSA { len, hash } => key_names("rsa", &format!("{:?}", len)),
    };

    let (private_key, public_key) = generate_keypair(config);

    std::fs::write(output_dir.join(private), &private_key).expect("Failed to write private key");
    std::fs::write(output_dir.join(public), &public_key).expect("Failed to write public key");

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
    private_key: &str,
    public_key: &str,
    ca: Option<&RootCertStore>,
) -> anyhow::Result<Vec<u8>> {
    let subject_pkey = PKey::private_key_from_pem(private_key.as_bytes())?;
    let subject_pubkey = PKey::public_key_from_pem(public_key.as_bytes())?;

    if let Some(RootCertStore {
        root_cert,
        priv_key,
        pub_key,
    }) = ca
    {
        let root_cert = X509::from_pem(root_cert.as_bytes())?;
        let root_pkey = PKey::private_key_from_pem(priv_key.as_bytes())?;

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_pubkey(&subject_pubkey)?;

        let issuer_name = root_cert.subject_name();
        builder.set_issuer_name(issuer_name)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", name.as_str())?;
        let name = name_builder.build();
        builder.set_subject_name(&name)?;

        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        match alg {
            Generator::Ecdsa { curve, .. } => match curve {
                ECDSACurve::P256 => builder.sign(&root_pkey, MessageDigest::sha3_256())?,
                ECDSACurve::P384 => builder.sign(&root_pkey, MessageDigest::sha3_384())?,
            },
            Generator::ED25519 { .. } => builder.sign(&root_pkey, MessageDigest::sha3_256())?,
            Generator::RSA { hash, .. } => match hash {
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
        let key_pair = rcgen::KeyPair::from_pem(private_key).unwrap();

        let mut params = CertificateParams::new(vec![name]);
        params.key_pair = Some(key_pair);
        params.is_ca = IsCa::NoCa;

        match alg {
            Generator::Ecdsa { curve, .. } => match curve {
                ECDSACurve::P256 => params.alg = &rcgen::PKCS_ECDSA_P256_SHA256,
                ECDSACurve::P384 => params.alg = &rcgen::PKCS_ECDSA_P384_SHA384,
            },
            Generator::ED25519 { .. } => params.alg = &rcgen::PKCS_ED25519,
            Generator::RSA { hash, .. } => match hash {
                RSAHash::SHA256 => params.alg = &rcgen::PKCS_RSA_SHA256,
                RSAHash::SHA384 => params.alg = &rcgen::PKCS_RSA_SHA384,
                RSAHash::SHA512 => params.alg = &rcgen::PKCS_RSA_SHA512,
            },
        }

        let cert = Certificate::from_params(params).unwrap();

        let bytes = cert.serialize_pem().unwrap();

        Ok(bytes.as_bytes().to_vec())
    }
}
