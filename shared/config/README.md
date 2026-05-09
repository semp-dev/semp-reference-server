# shared/config/

`config.example.toml` is the deployment-time starting point. Both
implementations parse this same shape:

- `impl/go` uses `github.com/BurntSushi/toml`.
- `impl/ts` uses `smol-toml`.

The authoritative field reference is `../docs/config-schema.md`. If
you add a new field, document it there and update both impl parsers
in the same change.
