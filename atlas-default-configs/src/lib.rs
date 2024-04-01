use atlas_comm_mio::config::{MIOConfig, TcpConfig, TlsConfig};
use atlas_common::error::*;
use atlas_common::node_id::NodeId;
use atlas_common::peer_addr::PeerAddr;
use atlas_communication::config::ClientPoolConfig;
use atlas_communication::reconfiguration::NodeInfo;
use atlas_reconfiguration::config::ReconfigurableNetworkConfig;
use config::File;
use config::FileFormat::Toml;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::crypto::{
    get_client_config, get_client_config_replica, get_server_config_replica,
    get_tls_sync_server_config, read_own_keypair, read_pk_of,
};
use crate::settings::{
    get_network_config, read_node_config, NetworkConfig, PoolConfig, ReconfigurationConfig,
};

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

pub fn get_network_configurations(id: NodeId) -> Result<(MIOConfig, ClientPoolConfig)> {
    let tls_config = get_tls_config(id);

    let network = get_network_config(File::new("config/network.toml", Toml))?;

    let NetworkConfig {
        worker_count,
        pool_config,
        tcp_conns,
    } = network;

    let tcp_config = TcpConfig {
        network_config: tls_config,
        replica_concurrent_connections: tcp_conns.replica_concurrent_connections,
        client_concurrent_connections: tcp_conns.client_concurrent_connections,
    };

    Ok((
        MIOConfig {
            epoll_worker_count: worker_count as u32,
            tcp_configs: tcp_config,
        },
        pool_config.into(),
    ))
}

pub fn get_reconfig_config() -> Result<ReconfigurableNetworkConfig> {
    let node_conf = read_node_config(File::new("config/nodes.toml", Toml))?;

    let ReconfigurationConfig {
        own_node,
        bootstrap_nodes,
    } = node_conf;

    let node_id = NodeId(own_node.node_id);
    let node_type = own_node.node_type;
    let addr = PeerAddr::new(
        SocketAddr::V4(SocketAddrV4::new(
            own_node.ip.parse::<Ipv4Addr>()?,
            own_node.port,
        )),
        own_node.hostname,
    );

    let node_kp = read_own_keypair(&node_id)?;

    let mut known_nodes = vec![];

    for node in bootstrap_nodes {
        let node_id = NodeId(node.node_id);

        known_nodes.push(NodeInfo::new(
            node_id,
            node.node_type,
            read_pk_of(&node_id)?,
            PeerAddr::new(
                SocketAddr::V4(SocketAddrV4::new(node.ip.parse::<Ipv4Addr>()?, node.port)),
                node.hostname,
            ),
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
