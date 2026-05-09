# shared/

Language-neutral assets consumed by every implementation under `impl/`.

## Contents

- **`config/`**: example TOML config. Both impls' parsers consume this
  same shape; `docs/config-schema.md` is the authoritative reference.
- **`schema/`**: SQLite DDL for the server-side store. The TS impl
  loads these files directly. The Go impl carries a byte-identical
  inline copy in `impl/go/internal/store/schema.go` (Go's `go:embed`
  cannot reach outside its module).
- **`docs/`**: cross-impl contracts both implementations honor:
  - `config-schema.md`: TOML field reference.
  - `store-contract.md`: SQLite WAL settings, busy-timeout,
    single-process expectation, master-key envelope (Argon2id +
    AES-256-GCM parameters required for cross-impl DB compatibility).
  - `transport-handlers.md`: which HTTP / WS endpoints each impl
    serves and what wire shape they speak.
- **`scripts/`**: integration scripts.
- **`deploy/`**: operator deployment recipes (Dokploy, Coolify,
  Portainer/Caddy, Plesk). Runtime-agnostic; point at
  `docker/docker-compose.yml` and select the impl via
  `COMPOSE_PROFILES=go|ts`.
