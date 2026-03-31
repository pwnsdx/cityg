# cityg-runtime

Shared runtime seams for City-G deployment adapters.

This crate exists so reusable bootstrap and persistence contracts can be shared
between the native `cityg-api` runtime and the Cloudflare-oriented
`cityg-worker` runtime without making either depend on the other's
platform-specific concerns.
