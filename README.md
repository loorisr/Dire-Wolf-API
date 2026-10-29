# Dire Wolf API

`Dire Wolf API` is a small Go service that bridges a KISS feed to an HTTP API and simple Web UI. The feed can come from [Dire Wolf](https://github.com/wb2osz/direwolf) over TCP, a serial TNC, or the Bluetooth SPP port of a radio such as the VR-N76. It can also forward every received packet to a remote backend with a durable local spool.

See [API.md](API.md) for the full REST and WebSocket API documentation, including the forwarding contract.

## Requirements

- Go 1.26 or newer
- A KISS source: Dire Wolf exposing a KISS TCP port, a serial TNC, or a Bluetooth KISS TNC

## Run locally

From the project root:

```bash
go run . -kiss localhost:8001 -api :8080 -max 1000
```

Flags:

- `-config`: JSON configuration file (see below)
- `-kiss`: KISS source (see below), default `localhost:8001`
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

## KISS sources

The `-kiss` flag and the `kiss` configuration field accept several source
formats:

| Value | Transport | Platform |
|---|---|---|
| `localhost:8001` or `tcp://localhost:8001` | Dire Wolf KISS over TCP | Linux, Windows |
| `serial:COM5` | Bluetooth SPP COM port or USB serial TNC | Windows |
| `serial:/dev/ttyUSB0` | USB serial TNC | Linux |
| `serial:/dev/rfcomm0` | RFCOMM TTY created by `rfcomm bind` | Linux |
| `rfcomm://AA:BB:CC:DD:EE:FF` | native Bluetooth RFCOMM, explicit MAC, SDP channel discovery | Linux |
| `rfcomm://auto` | single paired SPP device, SDP channel discovery | Linux |

Serial sources use **19200 baud, 8N1** by default, which matches the VR-N76
documentation. Override the bitrate when needed:

```bash
go run . -kiss 'serial:COM7?baud=9600'
go run . -kiss 'serial:/dev/ttyUSB0?baud=1200'
```

### VR-N76 over Bluetooth

On the radio, enable Bluetooth and set **Settings → General Settings → TNC
Mode → KISS** before pairing. Keep the radio awake while the service is running;
the client reconnects automatically with exponential backoff if the link drops.

#### Linux (recommended: native RFCOMM)

Pair and trust the radio once:

```bash
bluetoothctl
agent on
default-agent
scan on
pair 38:D2:00:AA:BB:CC
trust 38:D2:00:AA:BB:CC
exit
```

Then start the service. No root privileges, `rfcomm bind`, TTY or Dire Wolf
instance are needed:

```bash
go run . -kiss 'rfcomm://38:D2:00:AA:BB:CC'
```

To avoid hardcoding the MAC, use `auto`. The client asks BlueZ for the only
paired or connected device that exposes the Serial Port (SPP) service:

```bash
go run . -kiss 'rfcomm://auto'
```

The RFCOMM channel is discovered automatically from the SDP record
(`sdptool search --bdaddr <MAC> SP`, with `sdptool records` as fallback). Append
`?channel=N` to force a channel. The resolved address and channel are logged at
connection time. If several SPP devices are paired, `auto` deliberately fails
instead of guessing; use the MAC in that case.

On the VR-N76, the SPP Dev service can be exposed on RFCOMM channel **1 or 4**.
The client discovers the current one automatically. The link also carries the
radio's Benshi control frames, which the client ignores as non-KISS data. If the
SPP service is absent, the radio is almost certainly not in KISS TNC mode (or is
asleep/out of range): select **Settings → General Settings → TNC Mode → KISS**
and keep the service connected. A radio that is asleep/out of range or not in
KISS mode is reported as `host is down` / `connection refused`; the client
retries with exponential backoff.

The VR-N76 may leave KISS TNC mode when the RFCOMM connection closes. Keep the
service running continuously, or re-enable KISS mode after a disconnect.

If native RFCOMM is unavailable on your BlueZ setup, create the RFCOMM TTY and
use the serial transport instead:

```bash
sudo rfcomm bind /dev/rfcomm0 38:D2:00:AA:BB:CC 1
go run . -kiss 'serial:/dev/rfcomm0?baud=19200'
# later: sudo rfcomm release 0
```

Some distributions keep the radio busy with the Bluetooth headset profile and
prevent the SPP data link from staying up. If the RFCOMM connection drops
immediately, disable that profile in `/etc/bluetooth/input.conf`:

```ini
[General]
Disable=Headset
```

Then restart Bluetooth (`sudo systemctl restart bluetooth`) and pair again.

#### Windows (Bluetooth COM port)

1. Pair the VR-N76 in **Settings → Bluetooth & devices**.
2. Open **More Bluetooth options → COM Ports → Add**.
3. Choose **Outgoing (computer initiates connection)**, select the VR-N76 and
   confirm. Note the assigned port, for example `COM7`.
4. Start the service:

```powershell
.\direwolf_api.exe -kiss "serial:COM7?baud=19200" -api :8080
```

To list Bluetooth serial ports from PowerShell:

```powershell
Get-CimInstance Win32_SerialPort |
  Where-Object { $_.Description -like '*Bluetooth*' } |
  Select-Object DeviceID, Description
```

`GET /api/status` shows the active source in `addr`, for example
`rfcomm://38:d2:00:aa:bb:cc?channel=auto` or `serial:COM7?baud=19200`.

For the complete VR-N76 / Direwolf test setup, RFCOMM channel discovery,
PCH/PipeWire audio routing and VOX timing results, see
[`docs/vr-n76-kiss-direwolf.md`](docs/vr-n76-kiss-direwolf.md).

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

For a VR-N76, replace `kiss` with the source shown above, for example
`"kiss": "rfcomm://auto"` (or an explicit MAC) on Linux or
`"kiss": "serial:COM7?baud=19200"` on Windows.

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
