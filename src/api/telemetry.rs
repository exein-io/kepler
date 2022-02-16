use tracing::subscriber::set_global_default;
use tracing::Subscriber;
use tracing_log::LogTracer;
use tracing_subscriber::EnvFilter;

/// Compose multiple layers into a `tracing`'s subscriber.
///
/// # Implementation Notes
///
/// We are using `impl Subscriber` as return type to avoid having to spell out the actual
/// type of the returned subscriber, which is indeed quite complex.
fn get_subscriber(default_env_filter: &str) -> impl Subscriber + Sync + Send {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_env_filter));
    tracing_subscriber::fmt().with_env_filter(filter).finish()
}

pub fn init_logger(default_env_filter: &str) -> Result<(), log::SetLoggerError> {
    let subscriber = get_subscriber(default_env_filter);
    LogTracer::init()?;
    set_global_default(subscriber).expect("Failed to set subscriber");
    Ok(())
}
