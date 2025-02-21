use clap::{Parser, ValueEnum};
use ext_config::{Config, File, FileFormat};
use log::{debug, info, error};
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

    /// What application to spin up
    #[arg(value_enum)]
    app: ApplicationToRun,

    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "proxy-config.toml")]
    config_path: String,
}

#[derive(Debug, Clone, ValueEnum)]
enum ApplicationToRun {
    ProxyWallet,
    PoolMint
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let args = Args::parse();
    if args.verbose {
        debug!("DEBUG {args:?}");
    }

    info!("Using config path: {}", args.config_path);

    let cancel_token = CancellationToken::new();

    match args.app {
        ApplicationToRun::ProxyWallet => {
            // Load config for ProxyWallet
            let config = Config::builder()
                .add_source(File::new(&args.config_path, FileFormat::Toml))
                .build()?;
            let settings = config.try_deserialize::<ProxyConfig>()?;
            info!("ProxyWallet Config: {:?}", &settings);

            proxy_wallet::run(settings, cancel_token.clone()).await?
        }
        ApplicationToRun::PoolMint => {
            // Load config for PoolMint

            // pool_mint::run(config).await?
        }
    }

    Ok(())
}
