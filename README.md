# Dire Wolf API

`Dire Wolf API` is a small Go service that bridges a [Dire Wolf](https://github.com/wb2osz/direwolf) KISS TCP feed to an HTTP API and simple Web UI.

See [API.md](API.md) for the full REST and WebSocket API documentation.

## Requirements

- Go 1.26 or newer
- A running Dire Wolf instance that exposes a KISS TCP port https://github.com/wb2osz/direwolf

## Run locally

From the project root:

```bash
go run . -kiss localhost:8001 -api :8080 -max 1000
```

Flags:

- `-kiss`: Dire Wolf KISS TCP address, default `localhost:8001`
- `-api`: HTTP listen address, default `:8080`
- `-max`: maximum packets kept in memory, default `1000`
- `-tls`: HTTPS/WSS listen address (e.g. `:8443`), disabled if empty
- `-cert`: TLS certificate file; if omitted a self-signed certificate is generated automatically
- `-key`: TLS private key file; if omitted a self-signed certificate is generated automatically

When the service is running, the web UI is available at:

```
http://localhost:8080
```

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
GOOS=windows GOARCH=amd64 go build -o build/ddirewolf_api.exe
```

This produces a Windows executable named `direwolf_api.exe`.

