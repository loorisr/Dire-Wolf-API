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
  "uptime": "2h15m30s"
}
```

### `GET /api/status`

KISS connection state.

**Response:**

```json
{
  "status": "connected",
  "addr": "localhost:8001"
}
```

| `status` value    | Meaning                    |
|--------------------|----------------------------|
| `connected`        | KISS TCP link is up        |
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

## CORS

All JSON endpoints set `Access-Control-Allow-Origin: *`, allowing cross-origin requests from any host.
