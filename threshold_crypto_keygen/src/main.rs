use clap::Parser;
use threshold_crypto_keygen::ThresholdCryptoGeneratorArgs;

fn main() {
    let arguments = ThresholdCryptoGeneratorArgs::parse();

    println!("Running threshold key producer with arguments: {arguments:?}");

    threshold_crypto_keygen::generate_key_set(&arguments).unwrap();

    println!("Finished generating threshold keys.");
}
