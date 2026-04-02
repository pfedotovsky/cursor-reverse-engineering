# Cursor-Tap

[中文](./README.md) | English

A tool for intercepting and analyzing Cursor IDE's gRPC traffic. Decrypts TLS, deserializes protobuf, and displays AI conversations in real-time.

## Why

Cursor talks to its backend entirely via gRPC (Connect Protocol). The body is binary protobuf. Burp and Fiddler just show unreadable bytes. Cursor doesn't publish proto definitions either.

This tool decrypts traffic into readable JSON and shows each streaming frame in real-time.

## How It Works

1. **MITM Proxy** - Sits between Cursor and api2.cursor.sh, decrypts TLS with self-signed CA
2. **Proto Extraction** - Extracts proto definitions from Cursor's JS bundle (`protobuf-es` compiled output)
3. **Real-time Parsing** - Parses Connect Protocol envelope framing, deserializes each protobuf frame
4. **WebUI** - Pushes frames via WebSocket, four-panel layout for service tree / calls / frames / details

## Quick Start

### 1. Start the Proxy

```bash
g
o run ./cmd/cursor-tap start --http-parse
```

Listens on `localhost:8080` (HTTP proxy) and `localhost:9090` (REST API + WebSocket for the dev UI).

`--http-parse` enables MITM HTTP/gRPC decoding. Records are written to `<data-dir>/http.jsonl` by default so the UI can load and stream them. You can set another file with `--http-record /path/to/file.jsonl`.

If you start without `--http-parse` and without `--http-record`, the proxy still runs but **the web UI at localhost:3000 stays empty** (nothing is recorded or pushed).

### 2. Configure Cursor

```bash
# Windows
set HTTP_PROXY=http://localhost:8080
set HTTPS_PROXY=http://localhost:8080
set NODE_EXTRA_CA_CERTS=C:\path\to\ca.crt

# macOS/Linux
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export NODE_EXTRA_CA_CERTS=/path/to/ca.crt
```

CA certificate is auto-generated at `~/.cursor-tap/ca.crt` on first run.

### 3. Start WebUI

```bash
cd web
npm install
npm run dev
```

Open `http://localhost:3000`.

## Project Structure

```
├── cmd/cursor-tap/     # Proxy CLI entry point
├── internal/
│   ├── ca/             # CA certificate management
│   ├── proxy/          # HTTP CONNECT proxy
│   └── httpstream/     # gRPC parsing core
├── cursor_proto/       # Extracted proto definitions
└── web/                # Next.js frontend
```

## What You Can See

- `AiService/RunSSE` - AI conversation channel (thinking, text, tool calls)
- `BidiService/BidiAppend` - User messages and tool results
- `AiService/StreamCpp` - Code completion
- `CppService/RecordCppFate` - Completion accept/reject feedback
- `AiService/Batch` - User behavior telemetry
- And dozens more...

## Disclaimer

For educational and research purposes only.

## Related

Detailed reverse engineering notes: [cursor-true-reverse-notes-1.md](./cursor-true-reverse-notes-1.md) (Chinese)
