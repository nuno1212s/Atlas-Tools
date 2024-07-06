use atlas_common::error::*;
use atlas_common::node_id::NodeType;
use config::{Config, Source};
use serde::Deserialize;

/// The node configuration should contain this information
#[derive(Deserialize, Clone, Debug)]
pub struct Node {
    pub node_id: u32,
    pub ip: String,
    pub port: u16,
    pub hostname: String,
    pub node_type: NodeType,
}

/// Configuration about the node
#[derive(Deserialize, Clone, Debug)]
pub struct ReconfigurationConfig {
    pub own_node: Node,
    pub bootstrap_nodes: Vec<Node>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct PoolConfig {
    ///The max size for batches of client operations
    pub batch_limit: usize,
    ///How many clients should be placed in a single collecting pool (seen in incoming_peer_handling)
    pub clients_per_pool: usize,
    /// The size of the request queue for each client
    pub per_client_bound: usize,
    ///The timeout for batch collection in each client pool.
    /// (The first to reach between batch size and timeout)
    pub batch_timeout_micros: u64,
    ///How long should a client pool sleep for before attempting to collect requests again
    /// (It actually will sleep between 3/4 and 5/4 of this value, to make sure they don't all sleep / wake up at the same time)
    pub batch_sleep_micros: u64,

    pub channel_size: usize,
}

impl From<PoolConfig> for atlas_communication::config::ClientPoolConfig {
    fn from(config: PoolConfig) -> Self {
        atlas_communication::config::ClientPoolConfig::new(
            config.batch_limit,
            config.per_client_bound,
            config.clients_per_pool,
            config.batch_timeout_micros,
            config.batch_sleep_micros,
            config.channel_size,
        )
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct TCPConnConfig {
    /// How many concurrent connections should be established between replica nodes of the system
    pub replica_concurrent_connections: usize,
    /// How many client concurrent connections should be established between replica <-> client connections
    pub client_concurrent_connections: usize,
}

#[derive(Deserialize, Clone, Debug)]
pub struct NetworkConfig {
    // How many workers should our mio server have
    pub worker_count: usize,
    pub pool_config: PoolConfig,
    pub tcp_conns: TCPConnConfig,
    pub bind_addr: Option<Vec<BindAddr>>
}

#[derive(Deserialize, Clone, Debug)]
pub struct BindAddr {
    pub ip: String,
    pub port: u16
}

pub fn read_node_config<T>(source: T) -> Result<ReconfigurationConfig>
where
    T: Source + Sync + Send + 'static,
{
    let settings = Config::builder().add_source(source).build()?;

    let node_config: ReconfigurationConfig = settings.try_deserialize()?;

    Ok(node_config)
}

pub fn get_network_config<T>(source: T) -> Result<NetworkConfig>
where
    T: Source + Send + Sync + 'static,
{
    let config = Config::builder().add_source(source).build()?;

    let network: NetworkConfig = config.try_deserialize()?;

    Ok(network)
}
