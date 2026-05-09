# docker/

Multi-stage Dockerfiles for both reference-server implementations.

## Files

- **`go.Dockerfile`**: Go impl. `golang:1.26-alpine` build stage,
  `alpine:3.21` runtime. CGO disabled (pure-Go SQLite via
  `modernc.org/sqlite`). Output binary at `/usr/local/bin/semp-server`.
- **`ts.Dockerfile`**: TypeScript impl. `node:22-alpine` build and
  runtime stages. Build stage installs `python3 make g++` for
  `better-sqlite3`'s native compile; runtime stage drops them via
  stage separation. Entrypoint: `node /app/dist/main.js`.
- **`docker-compose.yml`**: orchestrates either impl via
  `COMPOSE_PROFILES=go` or `COMPOSE_PROFILES=ts`. Both services bind
  to host port 8443; only one profile runs at a time.

## Build

    docker build -f docker/go.Dockerfile -t semp-server:go .
    docker build -f docker/ts.Dockerfile -t semp-server:ts .

(Run from the repo root so the Dockerfile can `COPY impl/go`,
`COPY impl/ts`, and `COPY shared`.)

## Run

    docker run --rm -p 8443:8443 -v ./semp.toml:/etc/semp/semp.toml:ro \
        -v semp-data:/var/lib/semp semp-server:go

## Compose

Place a TOML file at `docker/fixtures/semp.toml` (untracked), then:

    COMPOSE_PROFILES=go docker compose -f docker/docker-compose.yml up -d
    COMPOSE_PROFILES=ts docker compose -f docker/docker-compose.yml up -d

The default with no profile starts nothing, which forces an explicit
choice. Mounting the fixture read-only at `/etc/semp` keeps secrets
out of the image layers.

## Operator deployment recipes

Higher-level recipes (Dokploy, Coolify, Portainer + Caddy, Plesk)
live under `shared/deploy/`. They are runtime-agnostic: each recipe
points at this `docker-compose.yml` and selects the impl via
`COMPOSE_PROFILES`.
