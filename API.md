# API Reference

## REST Endpoints

### `GET /api/packets`

Returns the most recent packets, newest first.

**Query parameters:**

| Param   | Type | Default | Description                 |
|---------|------|---------|-----------------------------|
| `limit` | int  | `100`   | Max packets to return       |
| `offset`| int  | `0`     | Skip N packets (from newest)|

**Response:**

```json
{
  "packets": [ ... ],
  "total": 1423,
  "limit": 100,
  "offset": 0
}
```

### `GET /api/packets/{id}`

Returns a single packet by its auto-increment ID.

**Response:** 200 with a [Packet](#packet) object, or 404.

### `GET /api/stats`

Aggregate packet counters and uptime.

**Response:**

```json
{
  "total_packets": 1423,
  "total_errors": 2,
  "start_time": "2026-05-06T18:00:00Z",
  "uptime": "2h15m30s",
  "forward": {
    "enabled": true,
    "state": "connected",
    "node_id": "fr-paris-1",
    "pending": 0,
    "spool_bytes": 40960,
    "sent": 1423,
    "retries": 5,
    "deadlettered": 0,
    "dropped": 0,
    "last_success": "2026-05-06T20:15:30Z",
    "last_attempt": "2026-05-06T20:15:30Z",
    "last_error": ""
  }
}
```

When forwarding is disabled, `forward` is still present with
`{"enabled": false, "state": "disabled"}`. The `forward` object is described in
[Forwarding stats](#forwarding-stats).

### `GET /api/status`

KISS source connection state.

**Response:**

```json
{
  "status": "connected",
  "addr": "rfcomm://38:d2:00:aa:bb:cc?channel=auto"
}
```

`addr` is the normalized source: a TCP `host:port`, `serial:<device>?baud=<rate>`,
`rfcomm://<address>?channel=<n>` or `rfcomm://auto?channel=<n>`.

| `status` value    | Meaning                    |
|--------------------|----------------------------|
| `connected`        | KISS link is up            |
| `connecting`       | Attempting to reconnect    |
| `disconnected`     | No active connection       |

### `GET /`

Embedded web UI with live packet list, detail inspector and map.

---

## WebSocket

### `ws://host:port/ws` / `wss://host:port/ws`

Sends a JSON [Packet](#packet) object for every received frame. On connect, replays the last 50 packets.

When served over HTTPS, the UI automatically uses `wss://`.

---

## Data Structures

### Packet

```json
{
  "id": 42,
  "timestamp": "2026-05-06T18:02:30.123456789Z",
  "port": 0,
  "raw_hex": "82888440...",
  "source": "N0CALL",
  "dest": "APRS",
  "via": "WIDE1-1*",
  "path": "N0CALL>APRS,WIDE1-1*",
  "pid": 240,
  "info_raw": "!4850.50N/00218.20E-",
  "aprs": { ... },
  "error": ""
}
```

| Field     | Type   | Description                                                    |
|-----------|--------|----------------------------------------------------------------|
| `id`      | int64  | Auto-increment packet ID                                       |
| `timestamp` | string | Server receive time (RFC 3339)                                |
| `port`    | int    | KISS TNC port (0-15)                                           |
| `raw_hex` | string | Raw frame bytes as hex                                         |
| `source`  | string | AX.25 source callsign                                          |
| `dest`    | string | AX.25 destination callsign                                     |
| `via`     | string | Comma-separated digipeater path, `*` = forwarded               |
| `path`    | string | TNC2-style path string (`SRC>DST,VIA1,VIA2`)                   |
| `pid`     | int    | AX.25 PID byte (omitted when 0)                                |
| `info_raw`| string | Raw info field text                                            |
| `aprs`    | object | Parsed APRS data (see [APRS Packet](#aprs-packet)), `null` for non-APRS frames |
| `error`   | string | AX.25 decode error message (empty on success)                  |

### APRS Packet

The `aprs` field is present when the AX.25 frame is a UI frame with PID `0xF0`.

```json
{
  "type": "position",
  "timestamp": "2026-05-06T18:02:30Z",
  "position": { ... },
  "message": { ... },
  "weather": { ... },
  "status": "En Route",
  "telemetry": "seq=1 v1=-12.500 v2=3.400",
  "comment": "Hello from APRS",
  "raw": "!4850.50N/00218.20E-Hello from APRS"
}
```

| Field      | Type   | Description                              |
|------------|--------|------------------------------------------|
| `type`     | string | Packet type (see below)                  |
| `timestamp`| string | Packet timestamp from info field (UTC)   |
| `position` | object | See [Position](#position)                |
| `message`  | object | See [Message](#message)                  |
| `weather`  | object | See [Weather](#weather)                  |
| `status`   | string | Status text                              |
| `telemetry`| string | Telemetry data as formatted string       |
| `comment`  | string | Free-text comment                        |
| `raw`      | string | Raw APRS info field                      |

**Packet types:**

| `type`       | Description                |
|--------------|----------------------------|
| `position`   | Uncompressed or compressed position report |
| `mic-e`      | Mic-E encoded position     |
| `message`    | Text message               |
| `status`     | Status report              |
| `object`     | APRS object                |
| `item`       | APRS item                  |
| `weather`    | Weather observation        |
| `telemetry`  | Telemetry data             |
| `nmea`       | NMEA GPS sentence          |
| `unknown`    | Unrecognized format        |

### Position

Present when the packet contains geographic coordinates.

```json
{
  "lat": 48.841667,
  "lon": 2.305000,
  "symbol": "/-",
  "speed": 45.0,
  "course": 180,
  "altitude": 120.0,
  "comment": "Hello"
}
```

| Field      | Type   | Unit     | Description                    |
|------------|--------|----------|--------------------------------|
| `lat`      | float  | degrees  | Latitude (negative = South)    |
| `lon`      | float  | degrees  | Longitude (negative = West)    |
| `symbol`   | string | –        | 2-char: symbol table + code    |
| `speed`    | float  | km/h     | Speed over ground              |
| `course`   | int    | degrees  | Heading 0-360, 0 = unknown     |
| `altitude` | float  | metres   | Altitude above sea level       |
| `comment`  | string | –        | Position comment               |

### Message

Present for APRS text messages, acknowledgements and rejects.

```json
{
  "addressee": "N0CALL",
  "text": "Hello world",
  "msg_id": "42",
  "is_ack": false,
  "is_rej": false
}
```

| Field       | Type   | Description                                  |
|-------------|--------|----------------------------------------------|
| `addressee` | string | Destination callsign (9 chars padded)        |
| `text`      | string | Message body                                 |
| `msg_id`    | string | Message ID (1-5 alphanumeric)                |
| `is_ack`    | bool   | `true` if this is an acknowledgement         |
| `is_rej`    | bool   | `true` if this is a reject                   |

### Weather

Weather observation fields. Only present when the packet contains weather data.

```json
{
  "wind_dir": 270,
  "wind_speed": 15.3,
  "wind_gust": 22.0,
  "temp": 18.5,
  "rain_hour": 0.25,
  "rain_day": 1.50,
  "humidity": 72,
  "pressure": 1013.2
}
```

| Field        | Type  | Unit     | Description                     |
|--------------|-------|----------|---------------------------------|
| `wind_dir`   | int   | degrees  | Wind direction (0-360)          |
| `wind_speed` | float | km/h     | Sustained wind speed            |
| `wind_gust`  | float | km/h     | Wind gust speed                 |
| `temp`       | float | °C       | Outside temperature             |
| `rain_hour`  | float | mm       | Rain in the last hour           |
| `rain_day`   | float | mm       | Rain in the last 24 hours       |
| `humidity`   | int   | %        | Relative humidity               |
| `pressure`   | float | hPa      | Barometric pressure             |

All fields are optional — only the data actually present in the packet is included.

---

## CSV Export

Pass `-csv <path>` to write every received packet to a CSV file in real time. The file is flushed after each packet.

### Usage

```bash
go run . -kiss localhost:8001 -api :8080 -csv packets.csv
```

### Columns

| Column                | Description                                  |
|-----------------------|----------------------------------------------|
| `id`                  | Auto-increment packet ID                     |
| `timestamp`           | Server receive time (RFC 3339 nanosecond)    |
| `port`                | KISS TNC port (0-15)                         |
| `source`              | AX.25 source callsign                        |
| `dest`                | AX.25 destination callsign                   |
| `via`                 | Comma-separated digipeater path              |
| `path`                | TNC2-style path string                       |
| `pid`                 | AX.25 PID (hex)                              |
| `info_raw`            | Raw info field text                          |
| `raw_hex`             | Full frame as hex                            |
| `error`               | AX.25 decode error message                   |
| `aprs_type`           | APRS packet type (position, weather, etc.)   |
| `lat`, `lon`          | Latitude/Longitude (degrees)                 |
| `symbol`              | APRS symbol table + code                     |
| `speed_kmh`           | Speed (km/h)                                 |
| `course_deg`          | Heading (0-360°)                             |
| `altitude_m`          | Altitude (meters)                            |
| `msg_addressee`       | Message destination callsign                 |
| `msg_text`            | Message body                                 |
| `msg_id`              | Message ID                                   |
| `weather_temp`        | Temperature (°C)                             |
| `weather_humidity`    | Humidity (%)                                 |
| `weather_pressure`    | Barometric pressure (hPa)                    |
| `weather_wind_dir`    | Wind direction (degrees)                     |
| `weather_wind_speed`  | Sustained wind speed (km/h)                  |
| `weather_wind_gust`   | Wind gust speed (km/h)                       |
| `weather_rain_hour`   | Rain last hour (mm)                          |
| `weather_rain_day`    | Rain last 24 hours (mm)                      |
| `status`              | Status text                                  |
| `comment`             | Free-text comment                            |

---

## Packet forwarding

When `forward.url` is configured, every received packet is sent to the backend
with one HTTP request per packet. Packets are written to a local spool before
delivery, so a backend outage or a service restart does not lose them.

A machine-readable OpenAPI 3.0 contract is available in
[`openapi.yaml`](openapi.yaml), with a ready-to-use request body in
[`backend-example-payload.json`](backend-example-payload.json).

### Configuration

Forwarding is configured in the JSON file (see `config.example.json`) or with
the `-forward*` flags. The token is read from `DIREWOLF_FORWARD_TOKEN`, then
`forward.token`, then `forward.token_file`.

| Key | Default | Description |
|---|---|---|
| `url` | – | `POST` endpoint, forwarding is disabled when empty |
| `health_url` | – | optional health check endpoint |
| `node_id` | hostname | station identifier included in every request |
| `spool_dir` | `forward-spool` | persistent spool directory |
| `spool_max_bytes` | `268435456` | spool size cap |
| `fsync` | `always` | `always`, `periodic` or `never` |
| `timeout` | `10s` | HTTP request timeout |
| `queue` | `4096` | in-memory queue between ingest and spool |
| `enqueue_timeout` | `2s` | max time ingest waits for queue space |
| `health_interval` | `30s` | health check period |
| `insecure` | `false` | skip TLS verification (testing only) |

### Request

```http
POST /v1/packets HTTP/1.1
Host: api.example.com
Authorization: Bearer <token>
Content-Type: application/json
Idempotency-Key: fr-paris-1:018f4c1e-6a9b-7c2d-8e3f-4a5b6c7d8e9f
User-Agent: direwolf-api/1.0
```

```json
{
  "schema_version": 1,
  "event_id": "018f4c1e-6a9b-7c2d-8e3f-4a5b6c7d8e9f",
  "seq": 42,
  "node_id": "fr-paris-1",
  "packet": {
    "id": 42,
    "timestamp": "2026-05-06T18:02:30.123456789Z",
    "port": 0,
    "raw_hex": "82888440...",
    "source": "N0CALL",
    "dest": "APRS",
    "via": "WIDE1-1*",
    "path": "N0CALL>APRS,WIDE1-1*",
    "pid": 240,
    "info_raw": "!4850.50N/00218.20E-",
    "aprs": { "...": "..." }
  }
}
```

| Field | Type | Description |
|---|---|---|
| `schema_version` | int | currently `1` |
| `event_id` | string | UUID generated before spooling; stable across retries and restarts |
| `seq` | int | local spool sequence, informational only |
| `node_id` | string | station identifier |
| `packet` | object | the [Packet](#packet) object, exactly as served by `/api/packets` |

All packets are forwarded, including frames that fail AX.25 decoding (they
still carry `raw_hex` and `error`) and frames without an APRS payload.

### Idempotency

Delivery is **at-least-once**. A crash between the backend's `2xx` and the local
acknowledgement causes the same packet to be sent again. The backend must
enforce a unique constraint on:

```
(node_id, event_id)
```

`packet.id` restarts at `1` after a process restart and must **not** be used as
an idempotency key.

The request header `Idempotency-Key` contains `<node_id>:<event_id>` for
convenience.

### Responses

| Status | Meaning | Client action |
|---|---|---|
| `200`, `201`, `202`, `204` | accepted | acknowledged, removed from the spool |
| `409` | duplicate | treated as acknowledged |
| `400`, `413`, `422` | invalid packet | written to `deadletter.ndjson`, delivery continues |
| `401`, `403` | authentication problem | kept in the spool, retried with a long backoff |
| `408`, `429` | transient | retried, `Retry-After` honored |
| `5xx`, timeout, network error | backend unavailable | retried with exponential backoff (1 s to 60 s, jitter) |
| other `4xx` | configuration problem | retried; check `url` and authentication |

Retries preserve the original `event_id` and the exact packet payload.

### Health check

When `health_url` is set, the service sends:

```http
GET <health_url>
Authorization: Bearer <token>
```

every `health_interval`. A `2xx` means reachable; `401`/`403` means
authentication is broken; any other status, timeout or network error means the
backend is unreachable. The health check never sends packets and never removes
anything from the spool.

### Forwarding states

| State | Meaning |
|---|---|
| `disabled` | no backend URL configured |
| `starting` | no delivery attempt or health check has completed yet |
| `connected` | last POST or health check succeeded |
| `degraded` | last attempt failed, retries are in progress |
| `disconnected` | three consecutive failures, or the health check is unreachable |
| `unauthorized` | the backend returned `401` or `403` |

A successful POST always wins over an older health check result.

### Forwarding stats

| Field | Type | Description |
|---|---|---|
| `enabled` | bool | forwarding is configured |
| `state` | string | one of the states above |
| `node_id` | string | station identifier |
| `pending` | int | packets written to the spool but not yet acknowledged |
| `spool_bytes` | int | current spool file size |
| `sent` | int | successful POSTs (including duplicates acknowledged with `409`) |
| `retries` | int | failed delivery attempts |
| `deadlettered` | int | packets rejected permanently by the backend |
| `dropped` | int | packets dropped because the queue or the spool cap was full |
| `last_success` | string | time of the last successful POST, omitted if never |
| `last_attempt` | string | time of the last delivery attempt, omitted if never |
| `last_error` | string | last error message, empty after a success |

### Spool and guarantees

```
<spool_dir>/
├── current.ndjson    # append-only queue
├── acked             # last acknowledged sequence
├── deadletter.ndjson # permanently rejected packets
└── .lock             # one process per spool directory
```

- Each entry is written and flushed **before** the first delivery attempt.
- On startup, everything after `acked` is replayed in order.
- The spool is compacted once every entry is acknowledged.
- When `spool_max_bytes` is reached, the oldest unacknowledged packets are
  dropped first and counted in `dropped`.
- Undelivered packets remain on disk across restarts. A clean shutdown drains
  the in-memory queue into the spool.
- The spool directory must be persistent and writable, and must not be shared
  by two processes. A stale `.lock` after a hard crash must be removed manually.

### Backend checklist

- Accept `POST` JSON at the configured URL and validate the Bearer token.
- Enforce a unique index on `(node_id, event_id)`; return `2xx` or `409` for
  duplicates.
- Return `400` or `422` for malformed packets, `429` with `Retry-After` when
  rate limited, and `5xx` for temporary failures.
- Expose an independent `GET` health endpoint returning `2xx`.
- Consider storing both `packet.timestamp` (edge receive time) and the backend
  receive time.

---

## CORS

All JSON endpoints set `Access-Control-Allow-Origin: *`, allowing cross-origin requests from any host.
