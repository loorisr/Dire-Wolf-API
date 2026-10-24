# Dire Wolf API

`Dire Wolf API` is a small Go service that bridges a [Dire Wolf](https://github.com/wb2osz/direwolf) KISS TCP feed to an HTTP API and simple Web UI. It can also forward every received packet to a remote backend with a durable local spool.

See [API.md](API.md) for the full REST and WebSocket API documentation, including the forwarding contract.

## Requirements

- Go 1.26 or newer
- A running Dire Wolf instance that exposes a KISS TCP port https://github.com/wb2osz/direwolf

## Run locally

From the project root:

```bash
go run . -kiss localhost:8001 -api :8080 -max 1000
```

Flags:

- `-config`: JSON configuration file (see below)
- `-kiss`: Dire Wolf KISS TCP address, default `localhost:8001`
- `-api`: HTTP listen address, default `:8080`
- `-max`: maximum packets kept in memory, default `1000`
- `-csv`: CSV output file path (e.g. `packets.csv`), disabled if empty
- `-tls`: HTTPS/WSS listen address (e.g. `:8443`), disabled if empty
- `-cert`: TLS certificate file; if omitted a self-signed certificate is generated automatically
- `-key`: TLS private key file; if omitted a self-signed certificate is generated automatically
- `-forward`: backend URL for packet forwarding, disabled if empty
- `-forward-health`: backend health check URL, disabled if empty
- `-forward-node`: station identifier sent to the backend, defaults to the hostname
- `-forward-token-file`: file containing the backend bearer token
- `-forward-spool`: persistent spool directory, default `forward-spool`
- `-forward-spool-max`: spool size cap in bytes, default `268435456` (256 MiB)
- `-forward-fsync`: spool flush mode, `always`, `periodic` or `never`, default `always`
- `-forward-timeout`: HTTP request timeout, default `10s`
- `-forward-queue`: in-memory queue size between ingest and spool, default `4096`
- `-forward-enqueue-timeout`: how long ingest waits for queue space, default `2s`
- `-forward-health-interval`: backend health check interval, default `30s`
- `-forward-insecure`: skip backend TLS certificate verification, for testing only

When the service is running, the web UI is available at:

```
http://localhost:8080
```

## Configuration file

Flags work on their own, but the service can also read a JSON file. Copy the
example and edit it:

```bash
cp config.example.json direwolf-api.json
```

The file is discovered in this order:

1. `-config <path>`
2. `DIREWOLF_CONFIG` environment variable
3. `./direwolf-api.json`
4. `/etc/direwolf-api/config.json`

Settings are merged with this priority:

```
built-in defaults < configuration file < environment variables < explicit flags
```

Unknown fields and invalid values are rejected at startup, so a typo cannot be
silently ignored. Changes to the file are applied after a restart.

All durations are strings such as `"10s"` or `"500ms"`. A complete example:

```json
{
  "kiss": "localhost:8001",
  "api": ":8080",
  "tls": "",
  "cert": "",
  "key": "",
  "max_packets": 1000,
  "csv": "",
  "forward": {
    "url": "https://api.example.com/v1/packets",
    "health_url": "https://api.example.com/v1/health",
    "node_id": "fr-paris-1",
    "token": "",
    "token_file": "/etc/direwolf-api/token",
    "spool_dir": "/var/lib/direwolf-api/spool",
    "spool_max_bytes": 268435456,
    "fsync": "always",
    "timeout": "10s",
    "queue": 4096,
    "enqueue_timeout": "2s",
    "health_interval": "30s",
    "insecure": false
  }
}
```

### Token

The backend token is resolved in this order:

1. `DIREWOLF_FORWARD_TOKEN` environment variable
2. `forward.token` in the configuration file
3. `forward.token_file`

The environment variable is preferred because a token passed on the command
line is visible in `ps` output and shell history. If the token is stored in the
configuration file, restrict it:

```bash
chmod 600 direwolf-api.json
```

The service logs a warning when the token is loaded from a config file that is
readable by group or others.

## Forwarding to a backend

Set `forward.url` (or `-forward`) and a token to enable forwarding. Every
received packet is appended to the spool first, then POSTed individually with an
`Idempotency-Key`. Delivery is **at-least-once**: if the backend is down, packets
accumulate on disk and are replayed in order after a restart.

```bash
export DIREWOLF_FORWARD_TOKEN='secret'
go run . \
  -kiss localhost:8001 \
  -api :8080 \
  -forward https://api.example.com/v1/packets \
  -forward-node fr-paris-1 \
  -forward-spool /var/lib/direwolf-api/spool
```

The exact request format, response codes and backend requirements are documented
in [API.md](API.md#packet-forwarding).

For backend implementation, the repository ships:

- [`openapi.yaml`](openapi.yaml): OpenAPI 3.0 contract with the full `Packet`
  schemas, headers, status codes and a generation-ready definition of
  `POST /v1/packets` and `GET /v1/health`. It can be used with `oapi-codegen`,
  `openapi-generator` or any OpenAPI-compatible tool.
- [`backend-example-payload.json`](backend-example-payload.json): a valid request
  body to test a handler with `curl`.

```bash
curl -X POST https://api.example.com/v1/packets \
  -H 'Authorization: Bearer secret' \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: fr-paris-1:018f4c1e-6a9b-7c2d-8e3f-4a5b6c7d8e9f' \
  -d @backend-example-payload.json
```

The backend must enforce a unique index on `(node_id, event_id)` and return `2xx`
or `409` for duplicates.

### Spool

The spool directory must be persistent (not `/tmp`) and writable by the service
user. It contains:

| File | Purpose |
|---|---|
| `current.ndjson` | append-only queue, one JSON entry per line |
| `acked` | last acknowledged sequence, replaced atomically |
| `deadletter.ndjson` | packets rejected with `400`, `413` or `422` |
| `.lock` | prevents two processes from sharing the directory |

The spool is capped by `spool_max_bytes`. When the cap is reached, the oldest
unacknowledged packets are dropped and counted in `/api/stats`; recent data is
always preferred. A stale `.lock` left by a hard crash must be removed manually.

`fsync: "always"` gives the strongest guarantee at negligible cost for APRS
rates. Use `"periodic"` on wear-sensitive storage (up to one second of packets
can be lost on a crash) or `"never"` for testing.

### Backend status in the UI

A second badge in the web UI shows the forwarding state:

| Badge | Meaning |
|---|---|
| `Backend: disabled` | no `forward.url` configured |
| `Backend: starting` | no delivery attempt or health check has completed yet |
| `Backend: connected` | last POST or health check succeeded |
| `Backend: degraded` | last attempt failed, retries are in progress |
| `Backend: disconnected` | three consecutive failures, or health check unreachable |
| `Backend: unauthorized` | the backend returned `401` or `403` |

When packets are waiting, the badge also shows the queue depth
(`Backend: degraded · 12 queued`). Hovering over it displays the last error.

## HTTPS and WSS

To enable HTTPS and WSS with an auto-generated self-signed certificate:

```bash
go run . -kiss localhost:8001 -api :8080 -tls :8443
```

To use your own certificate:

```bash
go run . -kiss localhost:8001 -api :8080 -tls :8443 -cert cert.pem -key key.pem
```

The HTTPS/WSS endpoint is then available at:

```
https://localhost:8443
wss://localhost:8443/ws
```

> **Note:** browsers will show a security warning for self-signed certificates.
> Before connecting, open `https://localhost:8443` directly in your browser and accept the security exception.
> The WSS connection will then work automatically from that point on.

The WebSocket client in the embedded UI automatically uses `wss://` when served over HTTPS.

## Build all targets

Build native Linux + Windows binaries for x86 and x64:

```bash
./build.sh
```

## Build for Linux

Build a native Linux binary with:

```bash
go build -o build/direwolf_api
```

If you want to be explicit about the target platform:

```bash
GOOS=linux GOARCH=amd64 go build -o build/direwolf_api
```

## Build for Windows

Build a Windows binary with:

```bash
GOOS=windows GOARCH=amd64 go build -o build/direwolf_api.exe
```

This produces a Windows executable named `direwolf_api.exe`.

## Tests

```bash
go test ./...
go test -race ./...
```

The OpenAPI contract can be validated with:

```bash
npx @redocly/cli lint openapi.yaml
```
