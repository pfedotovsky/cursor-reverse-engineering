# Decoding Cursor HTTP/2 gRPC Responses

How to decode a raw Cursor Agent HTTP/2 response from capture to readable JSON.

> **Background:** Cursor uses HTTP/2 with gRPC (not a system proxy), which makes traffic
> capture harder than HTTP/1.1. Once captured, the response body is a binary blob that
> requires multiple decoding stages.

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Raw HTTP/2 DATA frames                         │
│                   (captured via MITM / tcpdump)                    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                        Step 1 │  Extract & concatenate
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Single Base64 string                           │
│         AAAAAAQKAmoAAQAABaMfiwgAAAAAAAADfVbPi2RJEfbk...           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                        Step 2 │  Base64 decode
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Raw binary (21,568 bytes)                       │
│              00 00 00 00 04 0a 02 6a 00 01 00 00 05 a3 ...        │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                        Step 3 │  Parse gRPC frames
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Frame 0: [00][00 00 00 04] + 4 bytes payload                     │
│  Frame 1: [01][00 00 05 A3] + 1,443 bytes gzipped payload         │
│  Frame 2: [01][00 00 26 12] + 9,746 bytes gzipped payload         │
│  Frame 3: [00][00 00 00 AF] + 175 bytes payload                   │
│  ...                                                               │
│  Frame 47: [02][00 00 00 02] + 2 bytes (end-of-stream marker)     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                        Step 4 │  Gzip decompress (if compressed flag = 1)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Raw protobuf bytes per frame                      │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                        Step 5 │  Protobuf unmarshal → agent.v1.AgentServerMessage
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  {                                                                 │
│    "interactionUpdate": {                                          │
│      "textDelta": {                                                │
│        "text": "Creating a simple markdown file..."                │
│      }                                                             │
│    }                                                               │
│  }                                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Step-by-Step

### Step 1 — Extract the response body

Capture the HTTP/2 response for a Cursor Agent RPC (e.g. `POST /agent.v1.AgentService/RunSSE`).
Concatenate all HTTP/2 DATA frame payloads into a single blob. In our test case, the result
was saved as a single Base64 string in `response.txt`.

### Step 2 — Base64 decode

The extracted body is Base64-encoded. Decode it to get raw bytes:

```python
import base64

b64 = open("response.txt").read().strip()
raw = base64.b64decode(b64)
# → 21,568 bytes
```

### Step 3 — Parse gRPC length-prefixed frames

The raw bytes are a **stream of gRPC frames**. Each frame has a 5-byte header:

```
┌──────────┬──────────────────────┬─────────────────────┐
│ Byte 0   │ Bytes 1-4            │ Bytes 5..5+length   │
│ Compress │ Length (big-endian)   │ Payload             │
│ Flag     │                      │                     │
├──────────┼──────────────────────┼─────────────────────┤
│ 0x00     │ raw protobuf         │                     │
│ 0x01     │ gzip-compressed      │                     │
│ 0x02     │ end-of-stream marker │ (usually "{}")      │
└──────────┴──────────────────────┴─────────────────────┘
```

Parse loop in Python:

```python
import struct

offset = 0
frames = []
while offset + 5 <= len(raw):
    compressed = raw[offset]
    length = struct.unpack(">I", raw[offset+1:offset+5])[0]
    payload = raw[offset+5 : offset+5+length]
    frames.append((compressed, payload))
    offset += 5 + length
```

In Go (from `internal/httpstream/grpc.go`):

```go
header := make([]byte, 5)
io.ReadFull(reader, header)
compressed := header[0] == 1
length := binary.BigEndian.Uint32(header[1:5])
payload := make([]byte, length)
io.ReadFull(reader, payload)
```

### Step 4 — Gzip decompress (conditional)

If the compressed flag byte is `0x01`, the payload is **gzip-compressed**. Decompress before
protobuf parsing:

```python
import gzip

if compressed == 1:
    payload = gzip.decompress(payload)
```

Most frames in a typical response are uncompressed (`0x00`). The large frames (system prompt,
user message with full context) tend to be gzipped.

### Step 5 — Protobuf unmarshal

Each decompressed payload is a serialized **`agent.v1.AgentServerMessage`** protobuf message
(defined in `cursor_proto/agent_v1.proto`).

Decode with Go using the generated types:

```go
import (
    agentv1 "github.com/burpheart/cursor-tap/cursor_proto/gen/agent/v1"
    "google.golang.org/protobuf/encoding/protojson"
    "google.golang.org/protobuf/proto"
)

msg := &agentv1.AgentServerMessage{}
proto.Unmarshal(payload, msg)

jsonBytes, _ := protojson.MarshalOptions{Multiline: true}.Marshal(msg)
fmt.Println(string(jsonBytes))
```

Or with `protoc --decode` from the command line:

```bash
cat frame.bin | protoc --decode agent.v1.AgentServerMessage \
    -I cursor_proto cursor_proto/agent_v1.proto
```

---

## Message Types in the Stream

`AgentServerMessage` is a `oneof` with these variants:

| Variant | Proto Field | Purpose |
|---------|-------------|---------|
| **InteractionUpdate** | `interaction_update` (1) | Streaming AI output: text deltas, thinking, tool calls, heartbeats, token counts |
| **ExecServerMessage** | `exec_server_message` (2) | File read/write/exec operations from the server |
| **ConversationCheckpointUpdate** | `conversation_checkpoint_update` (3) | Periodic conversation state snapshots for resumability |
| **KvServerMessage** | `kv_server_message` (4) | Content-addressable blob storage (system prompt, messages, file contents) |
| **ExecServerControlMessage** | `exec_server_control_message` (5) | Execution control signals |
| **InteractionQuery** | `interaction_query` (7) | Server queries to the client |

### InteractionUpdate subtypes

The most interesting variant. Its `oneof message` includes:

| Subtype | Field | Description |
|---------|-------|-------------|
| `textDelta` | 1 | Streamed text chunks of the assistant response |
| `partialToolCall` | 7 | Progressive tool call assembly (name, partial args) |
| `toolCallDelta` | 15 | Tool call argument streaming (e.g. file content being written) |
| `toolCallStarted` | 2 | Full tool call ready for execution |
| `toolCallCompleted` | 3 | Tool result with success/error and diffs |
| `thinkingDelta` | 4 | Thinking started signal (includes thinking style) |
| `thinkingCompleted` | 5 | Thinking finished (includes duration in ms) |
| `tokenDelta` | 8 | Incremental token usage counter |
| `heartbeat` | 13 | Keep-alive |
| `turnEnded` | 14 | End of the agent's turn |
| `stepStarted` | 16 | Step boundary start |
| `stepCompleted` | 17 | Step boundary end (includes duration) |

### KV blob storage pattern

Large payloads are **not** sent inline. Instead:

1. Server sends `kvServerMessage.setBlobArgs` with a **SHA-256 blob ID** and the blob data
2. `conversationCheckpointUpdate` references blobs by their hash
3. Blob data is often a JSON string containing the full conversation message (role, content, tool calls)

This is a content-addressable storage pattern that avoids duplicating large messages across
checkpoint frames.

---

## Example Decoded Stream

Annotated frame sequence from a real "Add a simple .md file" conversation:

```
Frame  0  interactionUpdate.heartbeat           — keep-alive
Frame  1  kvServerMessage.setBlobArgs            — system prompt blob (gzipped, 2.6KB)
Frame  2  kvServerMessage.setBlobArgs            — user message blob (gzipped, 24KB)
Frame  3  kvServerMessage.setBlobArgs            — conversation state reference
Frame  4  kvServerMessage.setBlobArgs            — user query + Lexical editor JSON
Frame  5  interactionUpdate.thinkingDelta        — thinking started (CODEX style)
Frame  6  interactionUpdate.thinkingCompleted    — thinking done (68ms)
Frame  7  interactionUpdate.textDelta            — "Creating a simple markdown file..."
Frame  8  interactionUpdate.tokenDelta           — +13 tokens
Frame  9  interactionUpdate.partialToolCall      — Write tool call starting
Frame 11  interactionUpdate.partialToolCall      — path: .../test.md
Frame 14  interactionUpdate.toolCallDelta        — content: "Test content\n"
Frame 16  interactionUpdate.toolCallStarted      — full Write(path, content) ready
Frame 17  execServerMessage.readArgs             — server reads file pre-write
Frame 22  execServerMessage.writeArgs            — server writes test.md
Frame 23  conversationCheckpointUpdate           — mid-turn checkpoint
Frame 24  interactionUpdate.toolCallCompleted    — write succeeded, diff result
Frame 26  kvServerMessage.setBlobArgs            — assistant message blob
Frame 27  kvServerMessage.setBlobArgs            — tool result blob
Frame 31  conversationCheckpointUpdate           — checkpoint: 12,145 / 200,000 tokens
Frame 32  interactionUpdate.thinkingDelta        — 2nd thinking round
Frame 33  interactionUpdate.thinkingCompleted    — 436ms
Frame 34  interactionUpdate.textDelta            — "Created `test.md` at th..."
Frame 36  interactionUpdate.textDelta            — "...e repo root..." + confidence
Frame 38  interactionUpdate.stepCompleted        — step 5 done (2,453ms)
Frame 43  interactionUpdate.turnEnded            — turn complete
Frame 44  conversationCheckpointUpdate           — final state, file tracking
Frame 47  end-of-stream                          — compressed=2, payload="{}"
```

---

## Key Takeaway

The HTTP/2 response format is **identical to HTTP/1.1** at the application layer:
same gRPC framing, same protobuf schema, same gzip-per-frame compression. The only
difference is the transport — HTTP/2 multiplexed streams vs. HTTP/1.1 chunked transfer
encoding. Your existing `internal/httpstream/grpc.go` logic (`ReadFrame` →
`decompressGzip` → `proto.Unmarshal`) handles both transports without modification.
