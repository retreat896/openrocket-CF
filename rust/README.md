# OpenRocket Cloud: Cloudflare Rust rewrite

This directory is a Cloudflare-only rewrite scaffold for the project. It uses:

- Rust for the Cloudflare Worker and Durable Object rooms
- Rust/Wasm in the browser
- Cloudflare D1 for users, projects, sharing, edits and snapshots
- Cloudflare Durable Object SQLite storage for each design room
- Cloudflare Assets for the generated frontend

It does not start Docker containers and does not use noVNC.

## Install

Requires Node.js, Rust, the `wasm32-unknown-unknown` target, and Wrangler.

```bash
cd rust
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --locked --version 0.2.130
cargo install worker-build --locked
npm install
npx wrangler d1 create openrocket-rust
```

Put the D1 database ID returned by Wrangler in `wrangler.toml`, then run:

```bash
npx wrangler d1 migrations apply openrocket-rust --local
npm run dev
```

For a remote database:

```bash
npx wrangler d1 migrations apply openrocket-rust --remote
npm run deploy
```

Set `PUBLIC_URL` to the deployed origin and configure `SESSION_SECRET` as a Wrangler secret:

```bash
npx wrangler secret put SESSION_SECRET
```

Accounts and password hashes are stored in D1. The Worker does not require an external identity provider.

## Current implementation

The first vertical slice includes:

- `.ork` import, export, attachment handling and plain/gzip/zip parsing
- A shared Rust model and operation type for `put`, `set`, `move` and `del`
- D1 project and member records
- Signed local session cookies
- Local email/password registration and login
- Durable Object project rooms with WebSocket clients
- Ordered, persisted edit operations
- A Rust/Wasm project dashboard and component editor shell

This rewrite is not a completed native OpenRocket engine. OpenRocket's Java simulation and component implementation remain outside the Rust rewrite. It is safe to deploy for the model-sharing slice, but the native flight model, aerodynamics, motor database and complete component dialogs still need implementation or a separate verified engine integration.
