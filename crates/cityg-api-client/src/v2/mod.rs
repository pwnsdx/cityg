//! City-G v0.2 client: HTTP access to the delivery service and the member
//! driver built on `cityg-core`.

mod client;
mod invite;
mod member;

pub use client::{ClientError, DsClient};
pub use invite::{INVITE_PREFIX, INVITE_VERSION, InviteLink};
pub use member::{CONTENT_TYPE_TEXT, Member, SentMessage, SyncReport};

pub use cityg_core;
pub use cityg_proto;
