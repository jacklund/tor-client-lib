//! # Tor Client Lib
//! This is a client library for [Tor](https://www.torproject.org/), which allows you to interact programmatically with a Tor server, using its [API](https://github.com/torproject/torspec/blob/main/control-spec.txt).
//! ## Installation
//! To add it to your existing project:
//! ```bash
//! cargo add tor_client_lib
//! ```
//! ## Commands Supported
//! This library currently supports a small (but useful) subset of the full API, namely:
//! - AUTHENTICATE
//! - AUTHCHALLENGE
//! - GETINFO
//! - PROTOCOLINFO
//! - ADD_ONION
//! - DEL_ONION
//!
//! If you'd like to see more functions supported, please either submit an issue request or a PR.
//!
//! ## Example Code
//! ```
//! # use tokio;
//! use tor_client_lib::{
//!     control_connection::TorControlConnection,
//!     error::TorError,
//!     auth::TorAuthentication
//! };
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), TorError> {
//! // Connect to the Tor service running locally
//! let mut control_connection = TorControlConnection::connect("127.0.0.1:9051").await?;
//!
//! // Authenticate to the Tor server
//! control_connection.authenticate(TorAuthentication::SafeCookie(None)).await?;
//!
//! // Call the "GETINFO" command to get the Tor version number
//! let tor_version = control_connection.get_info("version").await?;
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod base64;
pub mod control_connection;
pub mod error;
pub mod key;

pub use crate::auth::TorAuthentication;
pub use crate::control_connection::{OnionService, TorControlConnection};
pub use crate::error::TorError;
pub use crate::key::{TorEd25519SigningKey, TorServiceId};
