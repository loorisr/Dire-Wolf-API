# Dire Wolf API

`Dire Wolf API` is a small Go service that bridges a [Dire Wolf](https://github.com/wb2osz/direwolf) KISS TCP feed to an HTTP API and simple Web UI.

## Requirements

- Go 1.21 or newer
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

When the service is running, the web UI is available at:

```bash
http://localhost:8080
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
