use std::net::ToSocketAddrs;

use anyhow::Context;
use config::File;
use config::FileFormat::Toml;
use regex::Regex;
use atlas_comm_mio::config::{MIOConfig, TcpConfig, TlsConfig};
use atlas_common::error::*;
use atlas_common::node_id::NodeId;
use atlas_common::peer_addr::PeerAddr;
use atlas_communication::config::ClientPoolConfig;
use atlas_communication::reconfiguration::NodeInfo;
use atlas_metrics::InfluxDBArgs;
use atlas_reconfiguration::config::ReconfigurableNetworkConfig;

use crate::crypto::{
    get_client_config, get_client_config_replica, get_server_config_replica,
    get_tls_sync_server_config, read_own_keypair, read_pk_of,
};
use crate::runtime_settings::RunTimeSettings;
use crate::settings::{BindAddr, get_network_config, NetworkConfig, read_node_config, ReconfigurationConfig};

pub mod crypto;
pub mod settings;
pub mod influx_db_settings;
pub mod runtime_settings;

#[macro_export]
macro_rules! addr {
    ($h:expr => $a:expr) => {{
        let server : Vec<_> = ::std::net::ToSocketAddrs::to_socket_addrs($a)
        .expect("Unable to resolve domain")
        .collect();

        let addr: ::std::net::SocketAddr = server.into_iter().next().expect("Resolved domain has no corresponding IPs?");
        (addr, String::from($h))
    }}
}

pub fn get_tls_config(id: NodeId) -> TlsConfig {
    println!("Reading client config");
    let client_config = get_client_config(id);
    println!("Reading tls sync server config");
    let server_config = get_tls_sync_server_config(id);
    println!("Reading client config replica");
    let client_config_replica = get_client_config_replica(id);
    println!("Reading server config replica");
    let server_config_replica = get_server_config_replica(id);

    TlsConfig {
        async_client_config: client_config_replica,
        async_server_config: server_config_replica,
        sync_server_config: server_config,
        sync_client_config: client_config,
    }
}

pub fn get_influx_configuration(id: Option<NodeId>) -> Result<InfluxDBArgs> {
    let influx_config = influx_db_settings::read_influx_db_config(File::new("config/influx_db.toml", Toml), id)?;
    
    Ok(influx_config.into())
}

pub fn get_runtime_configuration() -> Result<RunTimeSettings> {
    let runtime_settings = runtime_settings::read_runtime_settings(File::new("config/runtime_config.toml", Toml))?;
    
    Ok(runtime_settings)
}

pub fn get_network_configurations(id: NodeId) -> Result<(MIOConfig, ClientPoolConfig)> {
    println!("Reading tls config");
    let tls_config = get_tls_config(id);

    println!("Reading network config");
    let network = get_network_config(File::new("config/network.toml", Toml))?;

    let NetworkConfig {
        worker_count,
        pool_config,
        tcp_conns,
        bind_addr,
    } = network;

    let tcp_config = TcpConfig {
        bind_addrs: bind_addr.map(|addrs| {
            addrs.into_iter().flat_map(|BindAddr { ip, port }| {
                (ip, port).to_socket_addrs().expect("Failed to parse IP and port")
            }).collect()
        }),
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


fn parse_any_id(node_id: &str) -> NodeId {
    let regex = Regex::new(r".*?(\d+)$").expect("Failed to compile regex");

    let captured_item = regex.captures_iter(node_id)
        .next();
    
    captured_item
        .map(|cap| cap.extract())
        .map(|(_, [f1])| f1.parse().expect("Failed to parse node id"))
        .map(NodeId)
        .expect("Failed to parse node id")
}

pub fn get_reconfig_config() -> Result<ReconfigurableNetworkConfig> {
    let node_conf = read_node_config(File::new("config/nodes.toml", Toml))?;

    let ReconfigurationConfig {
        own_node,
        bootstrap_nodes,
    } = node_conf;

    let node_id = parse_any_id(&own_node.node_id);
    let node_type = own_node.node_type;
    let addr = PeerAddr::new(
        addr!(&own_node.hostname => format!("{}:{}", own_node.ip, own_node.port).as_str()).0,
        own_node.hostname,
    );

    let node_kp = read_own_keypair(&node_id).context("Reading own keypair")?;

    let mut known_nodes = vec![];

    for node in bootstrap_nodes {
        let node_id = parse_any_id(&node.node_id);

        known_nodes.push(NodeInfo::new(
            node_id,
            node.node_type,
            read_pk_of(&node_id).with_context(|| format!("Reading public key of {:?}", node_id))?,
            PeerAddr::new(
                addr!(&node.hostname => format!("{}:{}", node.ip, node.port).as_str()).0,
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
