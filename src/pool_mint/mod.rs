pub mod mining_pool;
pub mod template_receiver;

use core::panic;

use async_channel::{bounded, unbounded};
use tokio_util::sync::CancellationToken;

use crate::{error::PoolError, status};
use mining_pool::{get_coinbase_output, Pool, PoolConfiguration};
use template_receiver::TemplateRx;
use tracing::{error, info, warn};

pub async fn run(
    config: PoolConfiguration,
    cancel_token: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = PoolSv2::new(config, cancel_token);
    pool.start().await;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PoolSv2 {
    config: PoolConfiguration,
    cancel_token: CancellationToken,
}

impl PoolSv2 {
    pub fn new(config: PoolConfiguration, cancel_token: CancellationToken) -> PoolSv2 {
        PoolSv2 {
            config,
            cancel_token,
        }
    }

    pub async fn start(&self) -> Result<(), PoolError> {
        let config = self.config.clone();
        let (status_tx, status_rx) = unbounded();
        let (s_new_t, r_new_t) = bounded(10);
        let (s_prev_hash, r_prev_hash) = bounded(10);
        let (s_solution, r_solution) = bounded(10);
        let (s_message_recv_signal, r_message_recv_signal) = bounded(10);
        let coinbase_output_result = get_coinbase_output(&config);
        let coinbase_output_len = coinbase_output_result?.len() as u32;
        let tp_authority_public_key = config.tp_authority_public_key;
        TemplateRx::connect(
            config.tp_address.parse().unwrap(),
            s_new_t,
            s_prev_hash,
            r_solution,
            r_message_recv_signal,
            status::Sender::Upstream(status_tx.clone()),
            coinbase_output_len,
            tp_authority_public_key,
        )
        .await?;
        let pool = Pool::start(
            config.clone(),
            r_new_t,
            r_prev_hash,
            s_solution,
            s_message_recv_signal,
            status::Sender::DownstreamListener(status_tx),
        );

        // Start the error handling loop
        // See `./status.rs` and `utils/error_handling` for information on how this operates
        loop {
            tokio::select! {
                task_status = status_rx.recv() => {
                    let task_status: status::Status = task_status.unwrap();

                    match task_status.state {
                        // Should only be sent by the downstream listener
                        status::State::DownstreamShutdown(err) => {
                            error!(
                                "SHUTDOWN from Downstream: {}\nTry to restart the downstream listener",
                                err
                            );
                            break Ok(());
                        }
                        status::State::TemplateProviderShutdown(err) => {
                            error!("SHUTDOWN from Upstream: {}\nTry to reconnecting or connecting to a new upstream", err);
                            break Ok(());
                        }
                        status::State::Healthy(msg) => {
                            info!("HEALTHY message: {}", msg);
                        }
                        status::State::DownstreamInstanceDropped(downstream_id) => {
                            warn!("Dropping downstream instance {} from pool", downstream_id);
                            if pool
                                .safe_lock(|p| p.remove_downstream(downstream_id))
                                .is_err()
                            {
                                break Ok(());
                            }
                        }
                        // Because we merged two codebases, we need to handle
                        // all possible states here. The remaining states are not expected.
                        _ => panic!("This should not happen"),
                    }
                },
                _ = self.cancel_token.cancelled() => {
                    info!("Cancellation token triggered, shutting down...");
                    break Ok(());
                }
            }
        }
    }
}
