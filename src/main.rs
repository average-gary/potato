use clap::{Parser, ValueEnum};
use log::{debug, info};
use tokio;

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
    app: ApplicationToRun
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

    match args.app {
        ApplicationToRun::ProxyWallet => proxy_wallet::run().await?,
        ApplicationToRun::PoolMint => pool_mint::run().await?,
    }

    Ok(())
}
