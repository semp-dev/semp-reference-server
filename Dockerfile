FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /semp-server ./cmd/semp-server/

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S semp && adduser -S semp -G semp

COPY --from=build /semp-server /usr/local/bin/semp-server

RUN mkdir -p /etc/semp /var/lib/semp \
    && chown -R semp:semp /etc/semp /var/lib/semp

WORKDIR /var/lib/semp
USER semp

EXPOSE 8443

VOLUME ["/var/lib/semp"]

ENTRYPOINT ["semp-server"]
CMD ["-config", "/etc/semp/semp.toml"]
