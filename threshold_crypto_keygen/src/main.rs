use clap::Parser;
use threshold_crypto_keygen::ProgramArguments;

fn main() {
    
    let arguments = ProgramArguments::parse();
    
    println!("Running threshold key producer with arguments: {arguments:?}");
    
    threshold_crypto_keygen::generate_key_set(&arguments).unwrap();
    
    println!("Finished generating threshold keys.");
}