//! Embedded dashboard UI server.

pub(crate) mod account_proxy;
pub(crate) mod router;
pub(crate) mod server;
pub(crate) mod session;

pub(crate) use account_proxy::*;
pub(crate) use router::*;
pub(crate) use server::*;
pub(crate) use session::*;
