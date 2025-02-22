use clap::Parser;
use ext_config::{Config, File, FileFormat};
use log::{debug, info, error};
use pool_mint::mining_pool::PoolConfiguration;
use proxy_wallet::proxy_config::ProxyConfig;
use tokio;
use tokio_util::sync::CancellationToken;
use std::io::{self, Write};
use bitcoin::util::bip32::{ExtendedPubKey, DerivationPath};
use bitcoin::secp256k1::Secp256k1;
use std::str::FromStr;
use slip132::FromSlip132;

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

    /// The coinbase output address where mining rewards will be sent (SLIP-132 format)
    #[arg(short = 'c', long = "coinbase-output")]
    coinbase_output: Option<String>,

    /// The derivation path for the coinbase output (e.g. m/0/0)
    #[arg(short = 'd', long = "derivation-path", default_value = "m/0/0")]
    derivation_path: String,
}

fn derive_child_public_key(xpub: &ExtendedPubKey, path: &str) -> Result<ExtendedPubKey, String> {
    let secp = Secp256k1::new();
    DerivationPath::from_str(path)
        .map_err(|e| format!("Invalid derivation path: {}", e))
        .and_then(|derivation_path| {
            xpub.derive_pub(&secp, &derivation_path)
                .map_err(|e| format!("Derivation error: {}", e))
        })
}

fn validate_xpub(input: &str) -> Result<ExtendedPubKey, String> {
    ExtendedPubKey::from_slip132_str(input)
        .map_err(|_| format!("Invalid SLIP-132 extended public key"))
}

fn prompt_for_coinbase_output() -> io::Result<String> {
    loop {
        print!("Please enter the SLIP-132 xpub of the coinbase output: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        match validate_xpub(input) {
            Ok(_) => return Ok(input.to_string()),
            Err(e) => {
                println!("Error: {}. Please try again.", e);
                continue;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    let mut args = Args::parse();
    if args.verbose {
        debug!("DEBUG {args:?}");
    }

    // Validate or prompt for coinbase output
    let coinbase_output = if let Some(ref output) = args.coinbase_output {
        match validate_xpub(output) {
            Ok(xpub) => {
                // Derive child key
                match derive_child_public_key(&xpub, &args.derivation_path) {
                    Ok(child_key) => {
                        info!("Derived public key: {}", child_key.to_string());
                        output.clone()
                    },
                    Err(e) => {
                        error!("Failed to derive child key: {}", e);
                        prompt_for_coinbase_output()?
                    }
                }
            },
            Err(e) => {
                error!("Invalid coinbase output provided: {}", e);
                prompt_for_coinbase_output()?
            }
        }
    } else {
        prompt_for_coinbase_output()?
    };
    args.coinbase_output = Some(coinbase_output);

    let coinbase_output = args.coinbase_output.as_ref().unwrap();
    info!("Using coinbase output address: {}", coinbase_output);
    info!("Using derivation path: {}", args.derivation_path);
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
