//! Bounded, latest-value private telemetry shared by subscribers in one vault.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use futures_util::{future::BoxFuture, stream, StreamExt};
use tokio::sync::{watch, Semaphore};

use ciphervault_local_store::LocalVaultStore;
use ciphervault_storage::OperatorClient;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct TelemetryKey {
    // Never resolve process-global workspace state inside the sampling task.
    pub(super) db_path: PathBuf,
    pub(super) operators: Vec<String>,
}

#[derive(Clone, Copy)]
struct Limits {
    samplers: usize,
    subscribers: usize,
    operators: usize,
}

const PRIVATE_TELEMETRY_LIMITS: Limits = Limits {
    samplers: 16,
    subscribers: 64,
    operators: 32,
};
const PRIVATE_TELEMETRY_PERIOD: Duration = Duration::from_secs(3);
type Probe = Arc<dyn Fn(TelemetryKey) -> BoxFuture<'static, String> + Send + Sync>;

struct Sampler {
    sender: watch::Sender<Option<Arc<String>>>,
    task: tokio::task::AbortHandle,
}

impl Drop for Sampler {
    fn drop(&mut self) {
        // Stop the async sampler and its HTTP requests at the last subscriber.
        // Native blocking calls retain their separate process-wide permits.
        self.task.abort();
    }
}

pub(super) struct TelemetrySubscription {
    _sampler: Arc<Sampler>,
    receiver: watch::Receiver<Option<Arc<String>>>,
    initial: bool,
}

impl TelemetrySubscription {
    pub(super) async fn next(&mut self) -> Option<Arc<String>> {
        if self.initial {
            self.initial = false;
            if let Some(sample) = self.receiver.borrow_and_update().clone() {
                return Some(sample);
            }
        }
        loop {
            self.receiver.changed().await.ok()?;
            if let Some(sample) = self.receiver.borrow_and_update().clone() {
                return Some(sample);
            }
        }
    }
}

struct SamplerRegistry {
    entries: Mutex<HashMap<TelemetryKey, Weak<Sampler>>>,
    probe: Probe,
    period: Duration,
    limits: Limits,
}

impl SamplerRegistry {
    fn new(probe: Probe, period: Duration, limits: Limits) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            probe,
            period,
            limits,
        }
    }

    fn subscribe(&self, key: TelemetryKey) -> Result<TelemetrySubscription, &'static str> {
        if key.operators.len() > self.limits.operators
            || key.operators.iter().any(|endpoint| endpoint.len() > 2048)
        {
            return Err("The private telemetry operator limit has been reached");
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "Private telemetry registry is unavailable")?;
        entries.retain(|_, sampler| sampler.strong_count() > 0);
        if let Some(sampler) = entries.get(&key).and_then(Weak::upgrade) {
            if sampler.sender.receiver_count() >= self.limits.subscribers {
                return Err("The private telemetry subscriber limit has been reached");
            }
            return Ok(TelemetrySubscription {
                receiver: sampler.sender.subscribe(),
                _sampler: sampler,
                initial: true,
            });
        }
        if entries.len() >= self.limits.samplers {
            return Err("The private telemetry workspace limit has been reached");
        }

        let (sender, receiver) = watch::channel(None);
        let task_sender = sender.clone();
        let probe = Arc::clone(&self.probe);
        let task_key = key.clone();
        let period = self.period;
        let task = tokio::spawn(async move {
            loop {
                let sample = tokio::select! {
                    _ = task_sender.closed() => break,
                    sample = probe(task_key.clone()) => sample,
                };
                // One retained sample bounds memory for slow browsers. They
                // receive the newest observation rather than a growing queue.
                task_sender.send_replace(Some(Arc::new(sample)));
                tokio::select! {
                    _ = task_sender.closed() => break,
                    _ = tokio::time::sleep(period) => {}
                }
            }
        });
        let sampler = Arc::new(Sampler {
            sender,
            task: task.abort_handle(),
        });
        entries.insert(key, Arc::downgrade(&sampler));
        Ok(TelemetrySubscription {
            _sampler: sampler,
            receiver,
            initial: true,
        })
    }
}

static PRIVATE_TELEMETRY: OnceLock<SamplerRegistry> = OnceLock::new();
static TOKEN_PROBE: OnceLock<Arc<Semaphore>> = OnceLock::new();
static OPERATOR_PROBES: OnceLock<Arc<Semaphore>> = OnceLock::new();
static BACKLOG_PROBES: OnceLock<Arc<Semaphore>> = OnceLock::new();

pub(super) fn subscribe(key: TelemetryKey) -> Result<TelemetrySubscription, &'static str> {
    PRIVATE_TELEMETRY
        .get_or_init(|| {
            SamplerRegistry::new(
                Arc::new(|key| Box::pin(sample(key))),
                PRIVATE_TELEMETRY_PERIOD,
                PRIVATE_TELEMETRY_LIMITS,
            )
        })
        .subscribe(key)
}

async fn probe_operators(operators: Vec<String>) -> Vec<serde_json::Value> {
    let http = super::collectors::public_operator_http_client();
    let capacity = OPERATOR_PROBES
        .get_or_init(|| Arc::new(Semaphore::new(16)))
        .clone();
    let mut observations =
        stream::iter(operators.into_iter().enumerate().map(|(index, endpoint)| {
            let http = http.clone();
            let capacity = capacity.clone();
            async move {
                let _permit = capacity
                    .acquire()
                    .await
                    .expect("probe semaphore stays open");
                let start = Instant::now();
                let online = OperatorClient::with_http_client(endpoint.clone(), http)
                    .get_info()
                    .await
                    .is_ok();
                (
                    index,
                    serde_json::json!({
                        "endpoint": endpoint,
                        "online": online,
                        "latency_ms": online.then(|| start.elapsed().as_millis() as u64),
                    }),
                )
            }
        }))
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
    observations.sort_by_key(|observation| observation.0);
    observations
        .into_iter()
        .map(|observation| observation.1)
        .collect()
}

async fn sample(key: TelemetryKey) -> String {
    let token_probe = async {
        // PC/SC can block inside its native driver. Hold the permit inside the
        // blocking closure so a timeout or disconnected browser cannot create
        // repeated abandoned probes. At most one native call runs process-wide.
        let permit = TOKEN_PROBE
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone()
            .try_acquire_owned()
            .ok()?;
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            ciphervault_crypto::PcscHardwareToken::probe()
                .ok()
                .map(|token| token.is_some())
        });
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .ok()?
            .ok()?
    };
    let backlog = async move {
        let permit = BACKLOG_PROBES
            .get_or_init(|| Arc::new(Semaphore::new(4)))
            .clone()
            .acquire_owned()
            .await
            .ok()?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            LocalVaultStore::open(&key.db_path)
                .and_then(|store| store.pending_upload_summary())
                .ok()
        })
        .await
        .ok()?
    };
    let (operators, token_attached, pending) =
        tokio::join!(probe_operators(key.operators), token_probe, backlog);
    serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "operators": operators,
        "token_attached": token_attached,
        "pending_uploads": pending.map(|summary| serde_json::json!({
            "count": summary.count,
            "failed_count": summary.failed_count,
            "oldest_created_at_utc": summary.oldest_created_at_utc,
        })),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    async fn operator_stub() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let count = Arc::new(AtomicUsize::new(0));
        let signing_key = ciphervault_crypto::generate_signing_key();
        let mut info = ciphervault_storage::OperatorInfo {
            operator_id: "sampler-test".into(),
            operator_signing_pk_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            supported_version: 1,
            retention_terms: "synthetic test fixture".into(),
            identity_signature_hex: String::new(),
            identity_expires_at_utc: chrono::Utc::now().timestamp() as u64 + 3600,
        };
        info.identity_signature_hex =
            hex::encode(ciphervault_crypto::signatures::sign_with_domain(
                &signing_key,
                b"operator_identity",
                &info.identity_signing_bytes(),
            ));
        let app = axum::Router::new().route(
            "/v1/info",
            axum::routing::get({
                let count = count.clone();
                move || {
                    let count = count.clone();
                    let info = info.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        axum::Json(info)
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (endpoint, count, server)
    }

    fn network_registry(limits: Limits) -> SamplerRegistry {
        SamplerRegistry::new(
            Arc::new(|key| {
                Box::pin(async move {
                    serde_json::json!({
                        "workspace": key.db_path,
                        "operators": probe_operators(key.operators).await,
                    })
                    .to_string()
                })
            }),
            Duration::from_secs(60),
            limits,
        )
    }

    async fn next(subscription: &mut TelemetrySubscription) -> serde_json::Value {
        let sample = tokio::time::timeout(Duration::from_secs(5), subscription.next())
            .await
            .unwrap()
            .unwrap();
        serde_json::from_str(&sample).unwrap()
    }

    #[tokio::test]
    async fn subscribers_share_one_http_probe_and_keep_vaults_and_operator_configs_isolated() {
        let (alpha_endpoint, alpha_count, alpha_server) = operator_stub().await;
        let (beta_endpoint, beta_count, beta_server) = operator_stub().await;
        let registry = network_registry(PRIVATE_TELEMETRY_LIMITS);
        let alpha = TelemetryKey {
            db_path: PathBuf::from("alpha/vault.db"),
            operators: vec![alpha_endpoint.clone()],
        };
        let mut subscriptions = (0..12)
            .map(|_| registry.subscribe(alpha.clone()).unwrap())
            .collect::<Vec<_>>();
        for subscription in &mut subscriptions {
            let sample = next(subscription).await;
            assert_eq!(sample["workspace"], serde_json::json!(alpha.db_path));
            assert_eq!(sample["operators"][0]["endpoint"], alpha_endpoint);
            assert_eq!(sample["operators"][0]["online"], true);
        }
        assert_eq!(
            alpha_count.load(Ordering::SeqCst),
            1,
            "12 browser streams must share a single real HTTP probe"
        );

        let mut other_vault = registry
            .subscribe(TelemetryKey {
                db_path: PathBuf::from("beta/vault.db"),
                operators: vec![beta_endpoint.clone()],
            })
            .unwrap();
        let sample = next(&mut other_vault).await;
        assert_eq!(sample["operators"][0]["endpoint"], beta_endpoint);
        assert_eq!(beta_count.load(Ordering::SeqCst), 1);
        assert_ne!(sample["workspace"], serde_json::json!(alpha.db_path));

        let mut same_endpoint_other_vault = registry
            .subscribe(TelemetryKey {
                db_path: PathBuf::from("gamma/vault.db"),
                operators: alpha.operators.clone(),
            })
            .unwrap();
        assert_eq!(
            next(&mut same_endpoint_other_vault).await["workspace"],
            serde_json::json!("gamma/vault.db")
        );
        assert_eq!(
            alpha_count.load(Ordering::SeqCst),
            2,
            "workspace identity must be part of the sampler key"
        );

        let mut changed_config = registry
            .subscribe(TelemetryKey {
                db_path: alpha.db_path.clone(),
                operators: vec![beta_endpoint.clone()],
            })
            .unwrap();
        assert_eq!(
            next(&mut changed_config).await["operators"][0]["endpoint"],
            beta_endpoint
        );
        assert_eq!(
            beta_count.load(Ordering::SeqCst),
            2,
            "operator configuration changes require a distinct immutable sampler"
        );
        alpha_server.abort();
        beta_server.abort();
    }

    #[tokio::test]
    async fn registry_bounds_subscribers_workspaces_and_operators_and_reclaims_idle_entries() {
        let registry = network_registry(Limits {
            samplers: 1,
            subscribers: 2,
            operators: 1,
        });
        let key = TelemetryKey {
            db_path: PathBuf::from("alpha/vault.db"),
            operators: Vec::new(),
        };
        let first = registry.subscribe(key.clone()).unwrap();
        let second = registry.subscribe(key.clone()).unwrap();
        assert!(registry.subscribe(key.clone()).is_err());
        let other = TelemetryKey {
            db_path: PathBuf::from("beta/vault.db"),
            operators: Vec::new(),
        };
        assert!(registry.subscribe(other.clone()).is_err());
        assert!(registry
            .subscribe(TelemetryKey {
                db_path: key.db_path,
                operators: vec!["one".into(), "two".into()]
            })
            .is_err());
        drop(first);
        drop(second);
        let _new_workspace = registry.subscribe(other).unwrap();
        assert_eq!(registry.entries.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn slow_subscribers_receive_the_latest_sample_instead_of_accumulated_history() {
        let sequence = Arc::new(AtomicUsize::new(0));
        let registry = SamplerRegistry::new(
            Arc::new(move |_| {
                let sequence = sequence.clone();
                Box::pin(async move { (sequence.fetch_add(1, Ordering::SeqCst) + 1).to_string() })
            }),
            Duration::from_millis(10),
            PRIVATE_TELEMETRY_LIMITS,
        );
        let key = TelemetryKey {
            db_path: PathBuf::from("alpha/vault.db"),
            operators: Vec::new(),
        };
        let mut fast = registry.subscribe(key.clone()).unwrap();
        let mut slow = registry.subscribe(key).unwrap();
        let mut latest = 0;
        for _ in 0..5 {
            latest = next(&mut fast).await.as_u64().unwrap();
        }
        assert!(latest >= 5);
        assert!(next(&mut slow).await.as_u64().unwrap() >= latest);
    }

    #[tokio::test]
    async fn final_subscriber_cancels_an_in_flight_sampler() {
        struct Guard(Arc<Notify>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let entered = Arc::new(Notify::new());
        let cancelled = Arc::new(Notify::new());
        let registry = SamplerRegistry::new(
            Arc::new({
                let entered = entered.clone();
                let cancelled = cancelled.clone();
                move |_| {
                    let entered = entered.clone();
                    let cancelled = cancelled.clone();
                    Box::pin(async move {
                        let _guard = Guard(cancelled);
                        entered.notify_one();
                        std::future::pending::<String>().await
                    })
                }
            }),
            Duration::from_secs(60),
            PRIVATE_TELEMETRY_LIMITS,
        );
        let key = TelemetryKey {
            db_path: PathBuf::from("alpha/vault.db"),
            operators: Vec::new(),
        };
        let first = registry.subscribe(key.clone()).unwrap();
        let second = registry.subscribe(key).unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        drop(first);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), cancelled.notified())
                .await
                .is_err()
        );
        drop(second);
        tokio::time::timeout(Duration::from_secs(1), cancelled.notified())
            .await
            .unwrap();
    }
}
