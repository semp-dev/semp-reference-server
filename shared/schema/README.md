# shared/schema/

Numbered SQLite migration files applied in lexicographic order.

## Files

- `0001_init.sql`: initial schema. Tables: `domain_keys`, `user_keys`,
  `device_certificates`, `block_entries` (+ index `idx_block_user`),
  `inbox` (+ index `idx_inbox_address`), `delivered_ids`.

## Migration tracking

Both impls create a `schema_migrations(version INTEGER PRIMARY KEY,
applied_at TEXT)` table on first init and record one row per applied
file (`version` = leading integer in the filename).

## Cross-impl sync

The TS impl loads files from this directory directly. The Go impl
carries an inline string-literal copy in
`impl/go/internal/store/schema.go` because `go:embed` cannot reach
outside its module. **The inline Go copy MUST stay byte-identical to
`0001_init.sql` here.** When you change the schema, update both files
in the same commit.
