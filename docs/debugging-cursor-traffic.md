# Debugging Cursor Network Traffic

This document consolidates findings from debugging Cursor IDE's network traffic through a local proxy (2026-03-30 — 2026-03-31).

## The Core Problem

Cursor communicates with its backend via gRPC over HTTP/2. Intercepting this traffic to see agent conversations and file edits requires:

1. routing Cursor traffic through a local proxy,
2. performing TLS MITM to decrypt HTTPS,
3. parsing HTTP/2 frames and protobuf payloads.

Each layer has its own failure modes documented below.

## HTTP/2 and Proxy Bypass

**Cursor ignores the system proxy when using HTTP/2.** Setting the macOS system proxy, environment variables (`HTTP_PROXY`/`HTTPS_PROXY`), or Cursor's `http.proxy` setting is not sufficient — Cursor's HTTP/2 connections bypass all of these.

The only reliable way to capture HTTP/2 traffic from Cursor is to use low-level interception tools that operate below the application layer, such as:

```bash
mitmproxy --mode local
```

This hooks outbound connections at the OS/network level rather than relying on the application to respect proxy settings.

**However, mitmproxy does not support bidirectional streaming**, which is exactly what Cursor uses for agent conversations (gRPC bidirectional streams over HTTP/2). This means mitmproxy can capture unary and server-streaming RPCs but will break or miss bidirectional streams like `BidiService/BidiAppend`.

**Therefore, to fully debug Cursor's HTTP/2 traffic, a custom proxy* — one that handles HTTP/2 bidirectional streaming natively while also performing TLS MITM and protobuf decoding.

## Cursor's Process Architecture

Cursor (an Electron app) runs multiple process types with different networking behavior:

| Process | Role | Proxy behavior |
|---------|------|----------------|
| Main/renderer | Dashboard, telemetry, metrics | Inherits `HTTP_PROXY` env vars from shell |
| Extension-host (retrieval-always-local) | AI retrieval, conversation stream | Uses its own HTTP client; reads `http.proxy` from settings.json |
| Extension-host (agent-exec) | Agent tool execution | Same as above |

The extension-host processes are where agent prompts, responses, and file-edit flows happen — the traffic that matters most.

Key observations:

- `HTTP_PROXY`/`HTTPS_PROXY` env vars only reliably affect the main Electron process.
- `http.proxy` in `settings.json` is the Cursor/VS Code-level setting that extension-host code can read.
- Even with both configured, extension-host processes were observed connecting directly to `ai-proxy.sec.yandex.net:443` in some sessions.
- When Cursor was forced to HTTP/1.1, agent traffic became visible through the proxy again — indicating the issue is HTTP/2-specific, not a universal proxy bypass.

## Proxy Setup Procedure

### 1. Start the proxy

If using cursor-tap:

```bash
go run ./cmd/cursor-tap start --http-parse --http-log 4
```

If using mitmproxy/mitmweb, ensure it listens on `127.0.0.1:8080`:

```bash
lsof -nP -iTCP:8080 -sTCP:LISTEN
```

### 2. Configure Cursor settings

In `~/Library/Application Support/Cursor/User/settings.json`:

```json
{
  "http.proxy": "http://127.0.0.1:8080",
  "http.proxyStrictSSL": false
}
```

### 3. Kill all existing Cursor processes

```bash
pkill -x Cursor
pgrep -fal 'extension-host|Cursor'   # confirm nothing remains
```

### 4. Launch Cursor with proxy env vars

```bash
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
NODE_EXTRA_CA_CERTS=/Users/pfedotovsky/projects/cursor-tap/data/mitmproxy-ca-cert.pem \
/Applications/Cursor.app/Contents/MacOS/Cursor /Users/pfedotovsky/projects/cursor-tap
```

Both layers are needed: env vars for the main process, `http.proxy` for extension-host.

### 5. Trust the MITM CA

`NODE_EXTRA_CA_CERTS` may not propagate to all child processes. Trust the CA in the macOS login keychain:

```bash
security add-trusted-cert -d -r trustRoot \
  -k "/Users/pfedotovsky/Library/Keychains/login.keychain-db" \
  "/Users/pfedotovsky/projects/cursor-tap/data/mitmproxy-ca-cert.pem"
```

Before this trust was applied, the proxy logged repeated `client handshake: remote error: tls: unknown certificate` failures for `api3.cursor.sh` and `api2.cursor.sh`.

### 6. Verify the launch

Confirm the running Cursor process has the env vars:

```bash
ps eww -p "$(pgrep -x Cursor)"
```

Output must contain `HTTP_PROXY`, `HTTPS_PROXY`, and `NODE_EXTRA_CA_CERTS`. If they are absent, you are looking at a stale/wrong instance.

## Verification

### Check extension-host connections

```bash
pgrep -fal 'extension-host'
lsof -nP -a -p <PID> -iTCP -sTCP:ESTABLISHED
```

**Success:** connections to `127.0.0.1:8080`
**Failure:** direct connections to `<remote-ip>:443`

### Trigger a unique agent edit

Ask Cursor to insert a unique marker string, then search:

```bash
rg 'MY_UNIQUE_MARKER' ~/.cursor-tap/data/http.jsonl
```

### Compare HTTP/1.1 vs HTTP/2

Run the same agent action under both transport modes and compare:

- socket destinations via `lsof`
- whether agent RPCs appear in proxy logs
- whether the edit text appears or only telemetry

If only HTTP/1.1 is visible, the issue is HTTP/2 observability, not proxy bypass.

## What the Proxy Can See

### Captured (via main process)

- `/aiserver.v1.AiService/ReportAiCodeChangeMetrics` — hashed edit telemetry
- `/aiserver.v1.AiService/ReportClientNumericMetrics`
- `/aiserver.v1.DashboardService/*` — teams, plugins, privacy, usage
- `/aiserver.v1.AnalyticsService/Batch` — Statsig analytics
- `/aiserver.v1.OnlineMetricsService/ReportAgentSnapshot`
- `api3.cursor.sh` HTTP/2 telemetry

### Not captured (when HTTP/2 is active)

- The actual agent conversation request (user prompt + context)
- The streaming AI response (tool calls with file edit content)
- `StreamChat`, `CreateConversationTurn`, or similar RPCs

### Edit telemetry shape

When an edit is detected, the proxy sees a `ReportAiCodeChangeMetrics` call with:

```json
{
  "changes": [{
    "changeId": "844550d9",
    "source": "COMPOSER",
    "metadata": [{
      "fileExtension": "txt",
      "linesAdded": 1,
      "changeHashes": ["1e790efa"]
    }],
    "totalLinesAdded": 1
  }]
}
```

The literal edited text is **not** transmitted — only hashed summaries.

## Code Changes for Debugging

### HTTP/2 parser widened (`internal/httpstream/parser_h2.go`)

- Added a debug fallback so HTTP/2 `POST` traffic to `*.cursor.sh` is recorded even when it does not match the gRPC/Connect classifier.
- Preserved strict gRPC parsing for streams that match RPC detection.

### HTTP/1 body logging (`internal/httpstream/parser.go`)

- Raw body is now logged before protobuf decoding for both unary and framed gRPC streams.
- Factored common body logging through `logBodyData()`.

### Binary text extraction (`internal/httpstream/recorder.go`)

- Added `body_extracted_text` to JSONL records — extracts printable substrings from binary protobuf payloads for searchability.

## Summary

| Layer | Status |
|-------|--------|
| Proxy routing (main process) | Works with env vars |
| Proxy routing (extension-host) | Works with `http.proxy` in settings.json, but HTTP/2 bypasses it |
| TLS MITM | Works after OS-level CA trust |
| HTTP/1.1 traffic visibility | Full — agent traffic visible |
| HTTP/2 traffic visibility | Partial — Cursor ignores proxy settings; requires low-level interception |
| Literal edit text in logs | Not transmitted; only hashed telemetry |
| Bidirectional gRPC streams | Not supported by mitmproxy; requires custom proxy (cursor-tap) |

## Conclusion

For reliable Cursor traffic interception:

1. **HTTP/1.1 traffic** can be captured with standard proxy configuration (env vars + `http.proxy` setting).
2. **HTTP/2 traffic** requires low-level interception (`mitmproxy --mode local` or similar) because Cursor ignores proxy settings for HTTP/2 connections.
3. **Bidirectional gRPC streams** (the most interesting traffic) cannot be captured by mitmproxy — a custom proxy like cursor-tap that handles HTTP/2 bidirectional streaming is required.
4. **Edit content** is not transmitted verbatim over the network. Cursor applies edits locally and sends only hashed telemetry to the backend. To observe actual edit payloads, local Cursor-side instrumentation (IPC tracing, extension-host message inspection) would be needed.
