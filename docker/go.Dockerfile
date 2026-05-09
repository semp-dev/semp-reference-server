# syntax=docker/dockerfile:1
#
# Go implementation of the SEMP reference server.
# Build context: the repo root (so the Dockerfile can see impl/go/ and shared/).
#
#   docker build -f docker/go.Dockerfile -t semp-server:go .

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY impl/go/go.mod impl/go/go.sum ./impl/go/
RUN cd impl/go && go mod download
COPY impl/go ./impl/go
COPY shared ./shared
RUN cd impl/go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /semp-server ./cmd/semp-server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S semp && adduser -S semp -G semp \
 && mkdir -p /etc/semp /var/lib/semp \
 && chown -R semp:semp /etc/semp /var/lib/semp
COPY --from=build /semp-server /usr/local/bin/semp-server
USER semp
WORKDIR /var/lib/semp
EXPOSE 8443
VOLUME ["/var/lib/semp"]
ENTRYPOINT ["semp-server"]
CMD ["-config", "/etc/semp/semp.toml"]
