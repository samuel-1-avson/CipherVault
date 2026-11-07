//! Autonomous Predictive Swarm Healer.
//!
//! Evaluates dynamic chunk durability health scores across distributed operator
//! fleets and proactively schedules re-replication before hardware failure,
//! network partitioning, or lease expiration causes data degradation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Urgency level for autonomous swarm healing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HealingUrgency {
    /// Nominal state; chunk exceeds redundancy requirements
    Nominal,
    /// Proactive re-replication triggered due to degraded node latency or impending lease expiry
    Predictive,
    /// Urgent re-replication triggered due to replica loss below target threshold
    Critical,
}

/// An autonomous healing action planned by the swarm healer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealingAction {
    pub chunk_cid_hex: String,
    pub source_operator: String,
    pub target_operator: String,
    pub urgency: HealingUrgency,
    pub durability_score: f64,
    pub reason: String,
}

/// Dynamic health metrics for an individual operator fleet node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorTelemetry {
    pub endpoint: String,
    pub latency_ms: u64,
    pub consecutive_ping_failures: u32,
    pub is_online: bool,
    pub remaining_storage_quota_bytes: u64,
}

/// Dynamic object replication state across the operator fleet.
#[derive(Debug, Clone)]
pub struct ChunkReplicaState {
    pub cid: [u8; 32],
    pub present_on: Vec<String>,
    pub min_required_replicas: usize,
    pub lease_expiry_secs_remaining: HashMap<String, u64>,
}

/// Autonomous Swarm Healer engine.
pub struct PredictiveSwarmHealer {
    min_durability_threshold: f64,
    predictive_threshold: f64,
    max_tolerated_latency_ms: u64,
}

impl Default for PredictiveSwarmHealer {
    fn default() -> Self {
        Self {
            min_durability_threshold: 0.60,
            predictive_threshold: 0.85,
            max_tolerated_latency_ms: 1500,
        }
    }
}

impl PredictiveSwarmHealer {
    pub fn new(min_threshold: f64, predictive_threshold: f64) -> Self {
        Self {
            min_durability_threshold: min_threshold,
            predictive_threshold,
            max_tolerated_latency_ms: 1500,
        }
    }

    /// Computes the durability health score H(c) in [0.0, 1.0] for a chunk.
    pub fn compute_durability_score(
        &self,
        chunk: &ChunkReplicaState,
        telemetry: &HashMap<String, OperatorTelemetry>,
    ) -> (f64, HealingUrgency) {
        if chunk.present_on.is_empty() {
            return (0.0, HealingUrgency::Critical);
        }

        let mut available_healthy_count = 0.0;
        let mut degraded_node_detected = false;
        let mut expiring_lease_detected = false;

        for op in &chunk.present_on {
            let Some(node_telemetry) = telemetry.get(op) else {
                continue;
            };

            if !node_telemetry.is_online || node_telemetry.consecutive_ping_failures >= 3 {
                // Offline node contributes zero availability
                continue;
            }

            let mut node_weight = 1.0;

            // Latency penalty if node is lagging
            if node_telemetry.latency_ms > self.max_tolerated_latency_ms {
                node_weight *= 0.7;
                degraded_node_detected = true;
            }

            // Expiration penalty if lease expires in < 24 hours (86400s)
            if let Some(&ttl) = chunk.lease_expiry_secs_remaining.get(op) {
                if ttl < 86400 {
                    node_weight *= 0.6;
                    expiring_lease_detected = true;
                }
            }

            available_healthy_count += node_weight;
        }

        let raw_ratio = available_healthy_count / (chunk.min_required_replicas as f64);
        let score = raw_ratio.clamp(0.0, 1.0);

        let urgency = if score < self.min_durability_threshold
            || chunk.present_on.len() < chunk.min_required_replicas
        {
            HealingUrgency::Critical
        } else if score < self.predictive_threshold
            || degraded_node_detected
            || expiring_lease_detected
        {
            HealingUrgency::Predictive
        } else {
            HealingUrgency::Nominal
        };

        (score, urgency)
    }

    /// Evaluates fleet telemetry and plans autonomous healing actions for degraded chunks.
    pub fn plan_healing(
        &self,
        chunks: &[ChunkReplicaState],
        telemetry: &HashMap<String, OperatorTelemetry>,
        healthy_candidates: &[String],
    ) -> Vec<HealingAction> {
        let mut actions = Vec::new();

        for chunk in chunks {
            let (score, urgency) = self.compute_durability_score(chunk, telemetry);
            if urgency == HealingUrgency::Nominal {
                continue;
            }

            // Find a healthy source operator holding the chunk
            let source_opt = chunk.present_on.iter().find(|op| {
                telemetry
                    .get(*op)
                    .map(|t| t.is_online && t.latency_ms <= self.max_tolerated_latency_ms)
                    .unwrap_or(false)
            });

            let Some(source) = source_opt else {
                continue;
            };

            // Find a candidate target operator not already holding the chunk
            let target_opt = healthy_candidates.iter().find(|c| {
                !chunk.present_on.contains(c)
                    && telemetry.get(*c).map(|t| t.is_online).unwrap_or(false)
            });

            let Some(target) = target_opt else {
                continue;
            };

            let reason = match urgency {
                HealingUrgency::Critical => {
                    format!(
                        "Replica count ({}) below minimum quorum ({}); immediate healing",
                        chunk.present_on.len(),
                        chunk.min_required_replicas
                    )
                }
                HealingUrgency::Predictive => {
                    format!("Proactive re-replication: durability score {:.2} degraded below threshold {:.2}", score, self.predictive_threshold)
                }
                HealingUrgency::Nominal => unreachable!(),
            };

            actions.push(HealingAction {
                chunk_cid_hex: hex::encode(chunk.cid),
                source_operator: source.clone(),
                target_operator: target.clone(),
                urgency,
                durability_score: score,
                reason,
            });
        }

        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nominal_durability_score() {
        let healer = PredictiveSwarmHealer::default();
        let chunk = ChunkReplicaState {
            cid: [0x11; 32],
            present_on: vec![
                "http://op1:8101".into(),
                "http://op2:8101".into(),
                "http://op3:8101".into(),
            ],
            min_required_replicas: 3,
            lease_expiry_secs_remaining: HashMap::from([
                ("http://op1:8101".into(), 864000),
                ("http://op2:8101".into(), 864000),
                ("http://op3:8101".into(), 864000),
            ]),
        };

        let telemetry = HashMap::from([
            (
                "http://op1:8101".into(),
                OperatorTelemetry {
                    endpoint: "op1".into(),
                    latency_ms: 50,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
            (
                "http://op2:8101".into(),
                OperatorTelemetry {
                    endpoint: "op2".into(),
                    latency_ms: 60,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
            (
                "http://op3:8101".into(),
                OperatorTelemetry {
                    endpoint: "op3".into(),
                    latency_ms: 45,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
        ]);

        let (score, urgency) = healer.compute_durability_score(&chunk, &telemetry);
        assert_eq!(score, 1.0);
        assert_eq!(urgency, HealingUrgency::Nominal);

        let candidates = vec!["http://op4:8101".into()];
        let planned = healer.plan_healing(&[chunk], &telemetry, &candidates);
        assert!(
            planned.is_empty(),
            "No healing should be scheduled when nominal"
        );
    }

    #[test]
    fn test_predictive_healing_on_degraded_node_latency() {
        let healer = PredictiveSwarmHealer::default();
        let chunk = ChunkReplicaState {
            cid: [0x22; 32],
            present_on: vec![
                "http://op1:8101".into(),
                "http://op2:8101".into(),
                "http://op3:8101".into(),
            ],
            min_required_replicas: 3,
            lease_expiry_secs_remaining: HashMap::new(),
        };

        // op3 experiences degraded latency (2200ms)
        let telemetry = HashMap::from([
            (
                "http://op1:8101".into(),
                OperatorTelemetry {
                    endpoint: "op1".into(),
                    latency_ms: 50,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
            (
                "http://op2:8101".into(),
                OperatorTelemetry {
                    endpoint: "op2".into(),
                    latency_ms: 60,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
            (
                "http://op3:8101".into(),
                OperatorTelemetry {
                    endpoint: "op3".into(),
                    latency_ms: 2200,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
            (
                "http://op4:8101".into(),
                OperatorTelemetry {
                    endpoint: "op4".into(),
                    latency_ms: 40,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
        ]);

        let (score, urgency) = healer.compute_durability_score(&chunk, &telemetry);
        assert!(score < 1.0);
        assert_eq!(urgency, HealingUrgency::Predictive);

        let candidates = vec!["http://op4:8101".into()];
        let planned = healer.plan_healing(&[chunk], &telemetry, &candidates);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].urgency, HealingUrgency::Predictive);
        assert_eq!(planned[0].target_operator, "http://op4:8101");
    }

    #[test]
    fn test_critical_healing_on_replica_loss() {
        let healer = PredictiveSwarmHealer::default();
        // Only 2 replicas present, but 3 required
        let chunk = ChunkReplicaState {
            cid: [0x33; 32],
            present_on: vec!["http://op1:8101".into(), "http://op2:8101".into()],
            min_required_replicas: 3,
            lease_expiry_secs_remaining: HashMap::new(),
        };

        let telemetry = HashMap::from([
            (
                "http://op1:8101".into(),
                OperatorTelemetry {
                    endpoint: "op1".into(),
                    latency_ms: 50,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
            (
                "http://op2:8101".into(),
                OperatorTelemetry {
                    endpoint: "op2".into(),
                    latency_ms: 60,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
            (
                "http://op3:8101".into(),
                OperatorTelemetry {
                    endpoint: "op3".into(),
                    latency_ms: 50,
                    consecutive_ping_failures: 0,
                    is_online: true,
                    remaining_storage_quota_bytes: 1_000_000,
                },
            ),
        ]);

        let (score, urgency) = healer.compute_durability_score(&chunk, &telemetry);
        assert!(score < 0.7);
        assert_eq!(urgency, HealingUrgency::Critical);

        let candidates = vec!["http://op3:8101".into()];
        let planned = healer.plan_healing(&[chunk], &telemetry, &candidates);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].urgency, HealingUrgency::Critical);
        assert_eq!(planned[0].target_operator, "http://op3:8101");
    }
}
