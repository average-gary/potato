use clap::Parser;
use ext_config::{Config, File, FileFormat};
use log::{debug, info, error};
use pool_mint::mining_pool::PoolConfiguration;
use proxy_wallet::proxy_config::ProxyConfig;
use tokio;
use tokio_util::sync::CancellationToken;

mod pool_mint;
mod proxy_wallet;
mod status;
mod error;

#[derive(Parser, Debug)]
#[clap(author = "Gary Krause", version, about)]
/// Application configuration
struct Args {
    /// whether to be verbose
    #[arg(short = 'v')]
    verbose: bool,

    /// Path to the proxy wallet configuration file
    #[arg(short = 'p', long = "proxy-config", default_value = "proxy-config.toml")]
    proxy_config_path: String,

    /// Path to the pool mint configuration file 
    #[arg(short = 'm', long = "pool-mint-config", default_value = "pool-mint-config.toml")]
    pool_mint_config_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let args = Args::parse();
    if args.verbose {
        debug!("DEBUG {args:?}");
    }

    info!("Using proxy config path: {}", args.proxy_config_path);
    info!("Using pool mint config path: {}", args.pool_mint_config_path);

    let cancel_token = CancellationToken::new();
    let cancel_token_proxy = cancel_token.clone();
    let cancel_token_pool = cancel_token.clone();

    // Load configs for both services
    let proxy_config = Config::builder()
        .add_source(File::new(&args.proxy_config_path, FileFormat::Toml))
        .build()?;
    let proxy_settings = proxy_config.try_deserialize::<ProxyConfig>()?;
    info!("ProxyWallet Config: {:?}", &proxy_settings);

    let pool_config = Config::builder()
        .add_source(File::new(&args.pool_mint_config_path, FileFormat::Toml))
        .build()?;
    let pool_settings = pool_config.try_deserialize::<PoolConfiguration>()?;
    info!("PoolMint Config: {:?}", &pool_settings);

    // Run both services concurrently and handle Ctrl+C
    tokio::select! {
        proxy_result = proxy_wallet::run(proxy_settings, cancel_token_proxy) => {
            if let Err(e) = proxy_result {
                error!("ProxyWallet error: {}", e);
                cancel_token.cancel();
                return Err(e);
            }
        }
        pool_result = pool_mint::run(pool_settings, cancel_token_pool) => {
            if let Err(e) = pool_result {
                error!("PoolMint error: {}", e);
                cancel_token.cancel();
                return Err(e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, initiating graceful shutdown...");
            cancel_token.cancel();
        }
    }

    info!("Shutdown complete");
    Ok(())
}
