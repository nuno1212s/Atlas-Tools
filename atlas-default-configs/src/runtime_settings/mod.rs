use config::{Config, Environment, Source};
use config::Case::Upper;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct RunTimeSettings {
    pub threadpool_threads: usize,
    pub async_runtime_threads: usize,
}

pub fn read_runtime_settings<T>(source: T) -> atlas_common::error::Result<RunTimeSettings>
where
    T: Source + Send + Sync + 'static,
{
    let settings = Config::builder()
        .add_source(source)
        .add_source(Environment::with_convert_case(Upper))
        .build()?;

    let node_config: RunTimeSettings = settings.try_deserialize()?;

    Ok(node_config)
}