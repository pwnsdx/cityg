#![forbid(unsafe_code)]

//! City-G v0.3 client: HTTP access to the delivery service and the member
//! drivers built on `cityg-core`: [`Member`] (full) and [`LightMember`]
//! (without the public tree).

mod client;
mod invite;
mod light;
mod member;

pub use client::{ClientError, DsClient};
pub use invite::{INVITE_PREFIX, INVITE_VERSION, InviteLink};
pub use light::LightMember;
pub use member::{CONTENT_TYPE_TEXT, Member, SentMessage, StateSink, SyncReport};

pub use cityg_core;
pub use cityg_proto;
