use log::{debug, info, error};
use tokio;
use tokio_util::sync::CancellationToken;
use clap::Parser;

mod pool_mint;
mod proxy_wallet;
mod status;
mod error;
mod configuration;

use configuration::{Args, load_or_create_proxy_config, load_or_create_pool_config, process_coinbase_output};
use pool_mint::mining_pool::CoinbaseOutput;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let mut args = Args::parse();
    if args.verbose {
        debug!("DEBUG {args:?}");
    }

    let cancel_token = CancellationToken::new();
    let cancel_token_proxy = cancel_token.clone();
    let cancel_token_pool = cancel_token.clone();

    // Load or create default proxy config
    let proxy_settings = load_or_create_proxy_config(&args.proxy_config_path)?;
    info!("ProxyWallet Config: {:?}", &proxy_settings);

    // Load or create default pool config
    let mut pool_settings = load_or_create_pool_config(&args.pool_mint_config_path)?;
    info!("PoolMint Config: {:?}", &pool_settings);

    // Process coinbase output
    let coinbase_output = process_coinbase_output(&mut args)?;

    info!("Using coinbase output address: {}", coinbase_output);
    info!("Using derivation path: {}", args.derivation_path);
    info!("Using proxy config path: {}", args.proxy_config_path);
    info!("Using pool mint config path: {}", args.pool_mint_config_path);

    // Update pool settings with the validated coinbase output
    let coinbase_output = CoinbaseOutput::new(
        "P2WPKH".to_string(),  // Using P2WPKH for SLIP-132 xpub
        coinbase_output,
    );
    pool_settings.coinbase_outputs = vec![coinbase_output];

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
