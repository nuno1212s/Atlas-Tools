use clap::ValueEnum;

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum RSALength {
    #[value(name = "2048")]
    L2048,
    #[value(name = "4096")]
    L4096,
    #[value(name = "8192")]
    L8192,
}

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum RSAHash {
    #[value()]
    SHA256,
    #[value()]
    SHA384,
    #[value()]
    SHA512,
}
