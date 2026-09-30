//! Embedded dashboard UI server.

pub(crate) mod account_proxy;
pub(crate) mod collectors;
pub(crate) mod fastcdc_api;
pub(crate) mod files_api;
pub(crate) mod finality;
pub(crate) mod handlers;
pub(crate) mod metrics;
pub(crate) mod router;
pub(crate) mod scoped_api;
pub(crate) mod server;
pub(crate) mod session;
pub(crate) mod telemetry;

pub(crate) use account_proxy::*;
pub(crate) use collectors::*;
pub(crate) use fastcdc_api::*;
pub(crate) use files_api::*;
pub(crate) use finality::*;
pub(crate) use handlers::*;
pub(crate) use metrics::*;
pub(crate) use router::*;
pub(crate) use scoped_api::*;
pub(crate) use server::*;
pub(crate) use session::*;
