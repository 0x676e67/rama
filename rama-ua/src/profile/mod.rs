//! User Agent (UA) Profiles, mostly used for emulation.
//!
//! This module contains the profiles for the User Agent (UA) that are used for emulation.
//!
//! Learn more about User Agents (UA) and why Rama supports it
//! at <https://ramaproxy.org/book/intro/user_agent.html>.
//!

mod http;
pub use http::*;

#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
pub use tls::*;

mod js;
pub use js::*;

mod ua;
pub use ua::*;

mod db;
pub use db::*;

mod runtime_hints;
pub use runtime_hints::*;

#[cfg(feature = "embed-profiles")]
mod embedded_profiles;
#[cfg(feature = "embed-profiles")]
pub use embedded_profiles::*;
