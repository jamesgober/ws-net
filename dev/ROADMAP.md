# ws-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Master plan: C:/Dev/libraries/Rust/lang-collection/_lexersketch/ROADMAP.md and NEW-LIBS.md
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE)
Compiles, CI green, structure correct, no domain logic.
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP.

## v0.2.0 - Foundation
- [ ] Handshake (SHA-1 + base64 implemented in-crate until the owner's crypto library lands), framing, masking, fragmentation, ping/pong, close; Autobahn-style cases as data.

## v0.5.0 - Implementation
- [ ] permessage-deflate (with the owner's DEFLATE library), backpressure helpers.

## v0.9.0 - Hardening
- [ ] Fuzzing; full Autobahn conformance as a dev-only oracle.

## v1.0.0 - Stable
- [ ] Frozen after Studio ships on it (D18).
