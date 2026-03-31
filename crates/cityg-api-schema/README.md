# cityg-api-schema

Shared protobuf schema and request-routing helpers for the City-G HTTP API.

This crate centralizes the generated API wire types so `cityg-api`,
`cityg-api-client`, and `cityg-worker` can all reuse the same schema surface.
It also exposes neutral request-routing helpers that extract the room key
(`gid` or `we_epoch_id`) from room-scoped API requests without duplicating
protobuf parsing logic in each runtime adapter.
