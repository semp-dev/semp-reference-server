# syntax=docker/dockerfile:1
#
# TypeScript implementation of the SEMP reference server.
# Build context: the repo root (so the Dockerfile can see impl/ts/ and shared/).
#
#   docker build -f docker/ts.Dockerfile -t semp-server:ts .

FROM node:22-alpine AS build
WORKDIR /src
# better-sqlite3 is a native module: needs a compiler toolchain at build time.
RUN apk add --no-cache python3 make g++
COPY impl/ts/package.json impl/ts/package-lock.json ./impl/ts/
RUN cd impl/ts && npm ci
COPY shared ./shared
COPY impl/ts ./impl/ts
RUN cd impl/ts && npm run build && npm prune --omit=dev

FROM node:22-alpine
RUN addgroup -S semp && adduser -S semp -G semp \
 && mkdir -p /etc/semp /var/lib/semp \
 && chown -R semp:semp /etc/semp /var/lib/semp
WORKDIR /app
COPY --from=build /src/impl/ts/dist ./dist
COPY --from=build /src/impl/ts/node_modules ./node_modules
COPY --from=build /src/impl/ts/package.json ./package.json
COPY --from=build /src/shared ./shared
USER semp
WORKDIR /var/lib/semp
EXPOSE 8443
VOLUME ["/var/lib/semp"]
ENTRYPOINT ["node", "/app/dist/main.js"]
CMD ["-config", "/etc/semp/semp.toml"]
