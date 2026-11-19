# OpenRocket Cloud

OpenRocket Cloud runs the real OpenRocket 24.12 in the browser and adds local accounts,
Cloudflare storage and live multi-user design rooms. The service is free to use.

**Live deployment:** https://openrocket-rust.kris-adams3000.workers.dev

**Source and issue tracker:** https://github.com/retreat896/openrocket-CF

## How it works

- OpenRocket remains the official Java application, run in the browser by CheerpJ.
- The live-share bridge is compiled from `worker/bridge` and communicates with a
  Cloudflare Durable Object.
- Rust Worker code serves the frontend and APIs and coordinates D1 and R2.
- Cloudflare D1 stores accounts, projects, memberships, edit history and previews.
- Cloudflare R2 stores the large JAR assets and serves range requests.
- Every account and included feature is free. There is no subscription or checkout.

## Repository layout

```text
rust/
  crates/core/       Shared Rust model and .ork helpers
  crates/wasm/       Browser-facing Rust/WebAssembly package
  crates/worker/     Cloudflare Worker, D1 and Durable Object implementation
  migrations/        D1 schema migrations
  wrangler.toml      Worker, D1, R2 and Durable Object configuration
web/
  src/               Browser application and CheerpJ adapter
  public/            Images and browser assets
  features/          Public feature pages
  privacy.html       Privacy policy
  terms.html         Terms of service
worker/bridge/
  src/               Java live-share model and bridge
  web/               CheerpJ-specific browser fixes
scripts/
  build-web-jars.sh  Builds the OpenRocket and bridge JARs
  slim-openrocket-jar.py
  openrocket-startup.txt
  secret_scan.py      Pre-commit and CI credential scan
server/src/          Shared model, XML and template helpers
server/templates/    Blank rocket template
```

## Prerequisites

- Rust stable with `wasm32-unknown-unknown`
- Node.js and npm
- Wrangler
- A Cloudflare account for deployment
- Docker only when rebuilding the Java JARs

## Build and test

```bash
cd rust
cargo test -p orc-core
cargo check --target wasm32-unknown-unknown -p orc-wasm
cargo check --target wasm32-unknown-unknown -p orc-worker
npm run deploy
```

The deploy command builds the browser bundle, Rust WebAssembly packages and the Worker,
then uploads assets through Wrangler.

## Cloudflare setup

The deployment configuration uses:

- D1 database: `openrocket-rust`
- R2 bucket: `openrocket-rust-assets`
- Durable Object: `DESIGN_ROOMS`
- Worker secret: `SESSION_SECRET`

Apply migrations and set the secret as needed:

```bash
cd rust
npx wrangler d1 migrations apply openrocket-rust --remote
npx wrangler secret put SESSION_SECRET
npx wrangler deploy
```

The JAR objects must be uploaded to R2 under their configured names:

- `OpenRocket-web.jar`
- `orcloud-web-<build-tag>.jar`

The Worker serves both as range-request-compatible HTTP responses.

## Local accounts

Accounts use local email and password registration backed by D1. Passwords are salted and
hashed with PBKDF2-HMAC-SHA256. A signed HTTP-only session cookie authenticates API and
WebSocket requests.

The Account page includes a permanent account deletion action.

## Open-source licensing

This repository is licensed under **GPL-3.0-or-later**. See [LICENSE](LICENSE).

OpenRocket is copyright by the OpenRocket team and licensed under GPL-3.0. OpenRocket
Cloud is not affiliated with or endorsed by the OpenRocket project. Third-party libraries
and runtime components retain their own licenses.
