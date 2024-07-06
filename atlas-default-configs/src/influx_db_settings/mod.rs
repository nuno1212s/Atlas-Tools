use config::{Config, Source};
use serde::Deserialize;
use atlas_common::node_id::NodeId;
use atlas_metrics::InfluxDBArgs;
use crate::settings::ReconfigurationConfig;

#[derive(Deserialize, Debug, Clone)]
pub struct InfluxConfig {

    pub ip: String,
    pub db_name: String,
    pub user: String,
    pub password: String,
    pub node_id: u32,
    pub extra: Option<String>

}

impl From<InfluxConfig> for InfluxDBArgs {
    fn from(value: InfluxConfig) -> Self {
        InfluxDBArgs {
            ip: value.ip,
            db_name: value.db_name,
            user: value.user,
            password: value.password,
            node_id: NodeId::from(value.node_id),
            extra: value.extra,
        }
    }
}

pub fn read_influx_db_config<T>(source: T, id: Option<NodeId>) -> atlas_common::error::Result<InfluxConfig>
where
    T: Source + Sync + Send + 'static,
{
    let mut config_builder = Config::builder().add_source(source);
    
    if let Some(id) = id {
        config_builder = config_builder.set_override("node_id", id.0)?;
    }
    
    let settings = config_builder.build()?;
    

    let node_config: InfluxConfig = settings.try_deserialize()?;

    Ok(node_config)
}