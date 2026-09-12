//! # CipherVault Maintenance Service
//!
//! Provides zero-knowledge ciphertext auditing, replica repair across independent
//! operators, and lease retention runway management.

pub mod db;
pub mod engine;

pub use db::{AuditRecord, FleetSummary, MaintenanceDb, OperatorNodeRecord, TrackedVault};
pub use engine::{AuditReport, MaintenanceEngine, ObjectReplicaStatus, RepairResult};
