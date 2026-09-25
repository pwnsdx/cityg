#![forbid(unsafe_code)]

//! Request handlers of the City-G v0.2 delivery service.
//!
//! The native API (axum) and the Cloudflare Worker are thin transports over
//! these handlers: they route the HTTP path to a [`Route`], pass the body,
//! the bearer token and the clock, journal the returned record before
//! replying and notify subscribers when the log head moved.

mod handlers;
mod sessions;

pub use handlers::{
    Handled, ServiceConfig, core_error, create_room, handle_room_request, persist_record,
    room_error,
};
#[cfg(not(target_arch = "wasm32"))]
pub use handlers::{NativeRoomStore, NativeRoomStoreError};
pub use sessions::{Grant, SessionRegistry};

pub use cityg_proto::{ApiError, ErrorCode, Route};

#[cfg(test)]
mod tests;
