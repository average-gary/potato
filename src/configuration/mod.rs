use clap::Parser;
use ext_config::{Config, File, FileFormat};
use log::{debug, info, error, warn};
use bitcoin::util::bip32::{ExtendedPubKey, DerivationPath};
use bitcoin::secp256k1::Secp256k1;
use std::str::FromStr;
use slip132::FromSlip132;
use std::io::{self, Write};
use crate::pool_mint::mining_pool::{PoolConfiguration, CoinbaseOutput};
use crate::proxy_wallet::proxy_config::{ProxyConfig, DownstreamDifficultyConfig, UpstreamDifficultyConfig};
use key_utils::Secp256k1PublicKey;

#[derive(Parser, Debug)]
#[clap(author = "Gary Krause", version, about)]
/// Application configuration
pub struct Args {
    /// whether to be verbose
    #[arg(short = 'v')]
    pub verbose: bool,

    /// Path to the proxy wallet configuration file
    #[arg(short = 'p', long = "proxy-config", default_value = "proxy-config.toml")]
    pub proxy_config_path: String,

    /// Path to the pool mint configuration file 
    #[arg(short = 'm', long = "pool-mint-config", default_value = "pool-mint-config.toml")]
    pub pool_mint_config_path: String,

    /// The coinbase output address where mining rewards will be sent (SLIP-132 format)
    #[arg(short = 'c', long = "coinbase-output")]
    pub coinbase_output: Option<String>,

    /// The derivation path for the coinbase output (e.g. m/0/0)
    #[arg(short = 'd', long = "derivation-path", default_value = "m/0/0")]
    pub derivation_path: String,
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

pub fn create_default_pool_config() -> PoolConfiguration {
    PoolConfiguration {
        listen_address: "0.0.0.0:34254".to_string(),
        tp_address: "127.0.0.1:8442".to_string(),
        tp_authority_public_key: Some(Secp256k1PublicKey::from_str("9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72").unwrap()),
        authority_public_key: Secp256k1PublicKey::from_str("9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72").unwrap(),
        authority_secret_key: "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n".parse().unwrap(),
        cert_validity_sec: 3600,
        coinbase_outputs: vec![CoinbaseOutput::new(
            "P2WPKH".to_string(),
            "036adc3bdf21e6f9a0f0fb0066bf517e5b7909ed1563d6958a10993849a7554075".to_string(),
        )],
        pool_signature: "Stratum v2 SRI Pool".to_string(),
        #[cfg(feature = "test_only_allow_unencrypted")]
        test_only_listen_address_plain: "0.0.0.0:34250".to_string(),
    }
}

pub fn create_default_proxy_config() -> ProxyConfig {
    ProxyConfig {
        upstream_address: "127.0.0.1".to_string(),
        upstream_port: 34265,
        upstream_authority_pubkey: Secp256k1PublicKey::from_str("9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72").unwrap(),
        downstream_address: "0.0.0.0".to_string(), 
        downstream_port: 34255,
        max_supported_version: 2,
        min_supported_version: 2,
        min_extranonce2_size: 8,
        downstream_difficulty_config: DownstreamDifficultyConfig {
            min_individual_miner_hashrate: 10_000_000_000_000.0,
            shares_per_minute: 6.0,
            submits_since_last_update: 0,
            timestamp_of_last_update: 0,
        },
        upstream_difficulty_config: UpstreamDifficultyConfig {
            channel_diff_update_interval: 60,
            channel_nominal_hashrate: 10_000_000_000_000.0,
            timestamp_of_last_update: 0,
            should_aggregate: false,
        },
    }
}

pub fn load_or_create_proxy_config(config_path: &str) -> Result<ProxyConfig, Box<dyn std::error::Error>> {
    match Config::builder()
        .add_source(File::new(config_path, FileFormat::Toml))
        .build()
    {
        Ok(config) => Ok(config.try_deserialize::<ProxyConfig>()?),
        Err(e) => {
            warn!("Failed to load proxy config ({}), using defaults", e);
            Ok(create_default_proxy_config())
        }
    }
}

pub fn load_or_create_pool_config(config_path: &str) -> Result<PoolConfiguration, Box<dyn std::error::Error>> {
    match Config::builder()
        .add_source(File::new(config_path, FileFormat::Toml))
        .build()
    {
        Ok(config) => Ok(config.try_deserialize::<PoolConfiguration>()?),
        Err(e) => {
            warn!("Failed to load pool config ({}), using defaults", e);
            Ok(create_default_pool_config())
        }
    }
}

pub fn process_coinbase_output(args: &mut Args) -> Result<String, Box<dyn std::error::Error>> {
    let coinbase_output = if let Some(ref output) = args.coinbase_output {
        match validate_xpub(output) {
            Ok(xpub) => {
                // Derive child key
                match derive_child_public_key(&xpub, &args.derivation_path) {
                    Ok(child_key) => {
                        info!("Derived public key: {}", child_key.to_string());
                        output.to_string()
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
    args.coinbase_output = Some(coinbase_output.clone());
    Ok(coinbase_output)
} 