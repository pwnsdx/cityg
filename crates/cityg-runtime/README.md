# cityg-runtime

Transport-neutral request handlers of the City-G v0.3 delivery service.

The native server (`cityg-api`) and the Cloudflare Worker (`cityg-worker`)
route an HTTP path to a `Route`, pass the protobuf body, the bearer token and
the clock to `handle_room_request` (or `create_room`), journal the returned
record with `persist_record` before replying, and notify subscribers when
the log head moved.

- `ServiceConfig`: room limits, session lifetime, SessionAuth clock skew
  and compaction threshold; `ServiceConfig::from_config` reads the
  `[server]` section of a `CityGConfig`.
- `SessionRegistry`: bearer tokens obtained with a signed `SessionAuth`;
  a token stops working with the commit that removes its member or rotates
  its key.
- `NativeRoomStore`: memory or file store selected by the state path.
- `core_error` / `room_error`: the mapping of protocol and room errors to
  API error codes.
