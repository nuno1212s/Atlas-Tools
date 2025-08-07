use atlas_common::crypto::threshold_crypto::{
    PrivateKeyPart, PrivateKeySet, PublicKeyPart, PublicKeySet, SerializableKeyPart,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author = "Nuno Neto",
    version,
    about = "A key generation utility to facilitate the generation of threshold cryptography key sets"
)]
pub struct ThresholdCryptoGeneratorArgs {
    #[arg(short, long, value_name = "THRESHOLD", default_value_t = 1)]
    threshold: usize,
    #[arg(short, long, value_name = "NODE_COUNT", default_value_t = 4)]
    n: usize,
    #[arg(short, long, value_name = "OUTPUT_DIR", value_hint = clap::ValueHint::DirPath)]
    destination_dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct SerNodeKeyPair {
    node_index: usize,
    private_key: SerializableKeyPart,
    public_key: PublicKeyPart,
    public_key_set: PublicKeySet,
}

pub struct NodeKeyPair {
    pub node_index: usize,
    pub private_key: PrivateKeyPart,
    pub public_key: PublicKeyPart,
    pub public_key_set: PublicKeySet,
}

/// # [Errors]
/// Will throw errors related to the file creation and accessing
pub fn generate_key_set(args: &ThresholdCryptoGeneratorArgs) -> anyhow::Result<()> {
    let private_key_set = PrivateKeySet::gen_random(args.threshold);
    let pub_key_set = private_key_set.public_key_set();

    if !args.destination_dir.exists() {
        std::fs::create_dir_all(&args.destination_dir)?;
    }

    (0..args.n)
        .map(|node_index| {
            let priv_key_part = private_key_set.private_key_part(node_index);

            let pub_key_part = pub_key_set.public_key_share(node_index);

            SerNodeKeyPair {
                node_index,
                private_key: priv_key_part.into(),
                public_key: pub_key_part,
                public_key_set: pub_key_set.clone(),
            }
        })
        .try_for_each(|key_pair| {
            let buf = args
                .destination_dir
                .join(format!("node_{}.json", key_pair.node_index));

            let open_file = std::fs::File::create(buf)?;

            let mut buf_writer = BufWriter::new(open_file);

            serde_json::to_writer(&mut buf_writer, &key_pair)?;

            buf_writer.flush()?;

            Ok(())
        })
}

/// # [Errors]
/// Will throw errors related to the file reading and parsing
pub fn parse_key_pair(path: PathBuf) -> anyhow::Result<NodeKeyPair> {
    let file = std::fs::File::open(path)?;

    let node_key_pair: SerNodeKeyPair = serde_json::from_reader(&file)?;

    Ok(node_key_pair.into())
}

impl From<SerNodeKeyPair> for NodeKeyPair {
    fn from(value: SerNodeKeyPair) -> Self {
        Self {
            node_index: value.node_index,
            private_key: value.private_key.into(),
            public_key: value.public_key,
            public_key_set: value.public_key_set,
        }
    }
}
