use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use config::File;
use config::FileFormat::Toml;
use atlas_common::node_id::NodeId;
use atlas_common::error::*;
use atlas_common::peer_addr::PeerAddr;
use atlas_communication::config::{ClientPoolConfig, MioConfig, TcpConfig, TlsConfig};
use atlas_reconfiguration::config::ReconfigurableNetworkConfig;
use atlas_reconfiguration::message::NodeTriple;
use crate::crypto::{get_client_config, get_client_config_replica, get_server_config_replica, get_tls_sync_server_config, read_own_keypair, read_pk_of};
use crate::settings::{get_network_config, NetworkConfig, ReconfigurationConfig, read_node_config};

pub mod crypto;
pub mod settings;

pub fn get_tls_config(id: NodeId) -> TlsConfig {
    let client_config = get_client_config(id);
    let server_config = get_tls_sync_server_config(id);
    let client_config_replica = get_client_config_replica(id);
    let server_config_replica = get_server_config_replica(id);

    TlsConfig {
        async_client_config: client_config_replica,
        async_server_config: server_config_replica,
        sync_server_config: server_config,
        sync_client_config: client_config,
    }
}

pub fn get_mio_config(id: NodeId) -> Result<MioConfig> {
    let tls_config = get_tls_config(id);

    let network = get_network_config(File::new("config/network.toml", Toml))?;

    let NetworkConfig { worker_count, pool_config, tcp_conns } = network;

    let tcp_config = TcpConfig {
        network_config: tls_config,
        replica_concurrent_connections: tcp_conns.replica_concurrent_connections,
        client_concurrent_connections: tcp_conns.client_concurrent_connections,
    };

    let client_pool = ClientPoolConfig {
        batch_size: pool_config.batch_size,
        clients_per_pool: pool_config.clients_per_pool,
        batch_timeout_micros: pool_config.batch_timeout_micros,
        batch_sleep_micros: pool_config.batch_sleep_micros,
    };

    Ok(MioConfig {
        node_config: atlas_communication::config::NodeConfig {
            tcp_config,
            client_pool_config: client_pool,
        },
        worker_count,
    })
}

pub fn get_reconfig_config() -> Result<ReconfigurableNetworkConfig> {
    let node_conf = read_node_config(File::new("config/nodes.toml", Toml))?;

    let ReconfigurationConfig { own_node, bootstrap_nodes } = node_conf;

    let node_id = NodeId(own_node.node_id);
    let node_type = own_node.node_type;
    let addr = PeerAddr::new(SocketAddr::V4(SocketAddrV4::new(own_node.ip.parse::<Ipv4Addr>()?, own_node.port)), own_node.hostname);

    let node_kp = read_own_keypair(&node_id)?;

    let mut known_nodes = vec![];

    for node in bootstrap_nodes {
        let node_id = NodeId(node.node_id);

        known_nodes.push(NodeTriple::new(
            node_id,
            read_pk_of(&node_id)?.pk_bytes().to_vec(),
            PeerAddr::new(SocketAddr::V4(SocketAddrV4::new(node.ip.parse::<Ipv4Addr>()?, node.port)), node.hostname),
            node.node_type
        ));
    }

    Ok(ReconfigurableNetworkConfig {
        node_id,
        node_type,
        key_pair: node_kp,
        our_address: addr,
        known_nodes,
    })
}