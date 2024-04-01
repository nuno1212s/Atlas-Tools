use crate::generators::ecdsa::ECDSACurve;
use crate::generators::rsa::{RSAHash, RSALength};
use clap::{Args, Parser, Subcommand};
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

fn key_names(base: &str, kind: &str, number: usize) -> KeyNames {
    let make = |vis| format!("{}-{}-{}-{}", base, kind, vis, number);
    KeyNames {
        private: make("private"),
        public: make("public"),
        cert: make("cert"),
    }
}

#[derive(Parser, Debug)]
#[command(author = "Nuno Neto", version, about = "A key generation utility to quickly generate local signed certificates for secure communication", long_about = None)]
struct KeyGenConfig {
    #[command(flatten)]
    ranges: Ranges,
    #[arg(short, long, value_name = "OUTPUT_DIR", value_hint = clap::ValueHint::DirPath)]
    output_dir: PathBuf,
    #[arg(short, long, value_name = "WORK_THREADS", default_value_t = 1)]
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

fn main() {
    let config = KeyGenConfig::parse();

    if !config.output_dir.is_dir() {
        eprintln!(
            "out-dir '{}' is not a directory. Please create it or pass an existing directory.",
            config.output_dir.display()
        );

        return;
    }

    let mut pool = scoped_threadpool::Pool::new(config.work_threads as u32);

    println!("Running script with {:#?}", config);

    pool.scoped(|scope| {
        let config = &config;

        for replica_id in
            config.ranges.start_replica..config.ranges.start_replica + config.ranges.replica_count
        {
            scope.execute(move || {
                generate_key_for(
                    config,
                    config.output_dir.join(format!("{:?}/", replica_id)),
                    replica_id,
                )
            });
        }

        for client_id in
            config.ranges.start_client..config.ranges.start_client + config.ranges.client_count
        {
            scope.execute(move || {
                generate_key_for(
                    config,
                    config.output_dir.join(format!("{:?}/", client_id)),
                    client_id,
                )
            });
        }
    });

    println!("Generated all keys");
}

fn generate_key_for(config: &KeyGenConfig, output_dir: PathBuf, id: usize) {
    match &config.generator {
        Generator::Ecdsa { curve } => {
            let KeyNames {
                private,
                public,
                cert,
            } = key_names("ecdsa", &format!("{:?}", curve), id);

            generators::ecdsa::generate_ecdsa(
                &output_dir.join(private),
                &output_dir.join(public),
                curve,
            )
            .expect("Failed to generate ecdsa keys");
        }
        Generator::ED25519 => {
            let KeyNames {
                private: priv_file,
                public: pub_file,
                cert,
            } = key_names("ed", "25519", id);
            generators::ed25519::generate_ed25519(
                &output_dir.join(&priv_file),
                &output_dir.join(pub_file),
            )
            .expect("generate ed");

            if config.gen_certs {
                generate_x509(
                    &config.generator,
                    format!("atlas{id}"),
                    &output_dir.join(&priv_file),
                    &output_dir.join(cert),
                )
            }
        }
        Generator::RSA { .. } => {}
    }
}

pub(crate) fn generate_x509(
    alg: &Generator,
    name: String,
    private_key_path: &Path,
    cert_path: &Path,
) {
    let key_pair = std::fs::read(private_key_path).unwrap();
    let key_pair = rcgen::KeyPair::from_der(&key_pair).unwrap();

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

    let bytes = cert.serialize_der().unwrap();

    std::fs::write(cert_path, &bytes).unwrap();
}
