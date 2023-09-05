use config::{Config, Environment};
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct ApiSettings {
    pub address: String,
    pub port: u16,
}

impl ApiSettings {
    pub fn try_from_env() -> Result<Self, config::ConfigError> {
        Config::builder()
            .set_default("address", "0.0.0.0")?
            .set_default("port", 8000)?
            .add_source(Environment::with_prefix("KEPLER").prefix_separator("_"))
            .build()?
            .try_deserialize::<Self>()
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct DatabaseSettings {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
}

impl DatabaseSettings {
    pub fn try_from_env() -> Result<Self, config::ConfigError> {
        Config::builder()
            .set_default("port", 5432)?
            .add_source(Environment::with_prefix("DB").prefix_separator("_"))
            .build()?
            .try_deserialize::<Self>()
    }

    pub fn connection_string(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.database
        )
    }
}
