# 2Link Protocol Specification v0.1

Status: draft. Applies to protocol version `1` (V1: LAN, direct TCP).

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Conventions

- All multi-byte integers are unsigned and **big-endian** (network byte order).
- `u8`, `u16`, `u32`, `u64` denote unsigned integers of 8, 16, 32, 64 bits.
- `||` denotes byte concatenation.
- Strings are UTF-8, length-prefixed, never NUL-terminated.
- A receiver MUST treat any violation of a MUST rule in this document as a fatal
  protocol error for the connection (section 7).

## 2. Frame format

Every byte on a 2Link TCP connection belongs to a frame. A frame is a fixed
28-byte header followed by a payload of exactly `length` bytes.

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+---------------+---------------+---------------+---------------+
|    version    |     type      |     flags     |   reserved    |   0
+---------------+---------------+---------------+---------------+
|                           stream_id                           |   4
+---------------------------------------------------------------+
|                                                               |   8
+                            conn_id                            +
|                                                               |  12
+---------------------------------------------------------------+
|                                                               |  16
+                              seq                              +
|                                                               |  20
+---------------------------------------------------------------+
|                            length                             |  24
+---------------------------------------------------------------+
|                    payload (length bytes) ...                 |  28
```

| Field | Type | Rule |
|-------|------|------|
| `version` | u8 | MUST be `1`. |
| `type` | u8 | Frame type, section 3. Unknown values are fatal. |
| `flags` | u8 | No flags are defined in v0.1. MUST be `0`. |
| `reserved` | u8 | MUST be `0`. |
| `stream_id` | u32 | Logical stream, section 2.2. |
| `conn_id` | u64 | Connection identifier, section 2.3. |
| `seq` | u64 | Per-direction frame sequence number, section 5.3. |
| `length` | u32 | Payload length in bytes, including the AEAD tag if present. |

### 2.1 Size limits

| Constant | Value |
|----------|-------|
| `HEADER_SIZE` | 28 bytes |
| `MAX_PAYLOAD` | 524 288 bytes (512 KiB) |
| `AEAD_TAG_SIZE` | 16 bytes |
| `MAX_HANDSHAKE_PAYLOAD` | 65 535 bytes (Noise message limit) |

- A receiver MUST validate the full header before reading or allocating for the
  payload. A `length` above the limit for the frame type is fatal.
- An encrypted frame's `length` MUST be at least `AEAD_TAG_SIZE`.
- A receiver MUST NOT allocate memory sized from an unvalidated `length`.

`MAX_PAYLOAD` leaves room for a 256 KiB file chunk plus its metadata and tag.

### 2.2 Streams

| `stream_id` | Stream | Carries |
|-------------|--------|---------|
| `0` | Control | Handshake, pairing, keepalive, rekey, close |
| `1` | Messaging | Chat messages, acks, sync |
| `2 .. 2^32-1` | Transfer | One stream per file transfer |

Each frame type is valid on exactly one stream class (section 3). A frame on the
wrong stream is fatal.

In V1, control and messaging travel on the **primary** connection and transfer
streams on a separate **bulk** connection (section 6.4), so bulk traffic cannot
block chat behind it in a single TCP byte stream.

### 2.3 Connection ID

- The initiator picks `conn_id` as 64 random bits from a CSPRNG and sets it in its
  first `HANDSHAKE` frame.
- Every later frame on that TCP connection, in both directions, MUST carry the
  same `conn_id`. A mismatch is fatal.
- In V1 `conn_id` only binds frames to their connection. It does not provide
  connection migration; that needs the V2 UDP transport.

### 2.4 Parsing over TCP

TCP delivers a byte stream, not frames. A conforming parser MUST:

- buffer partial headers and partial payloads across reads;
- extract every complete frame from a single read;
- reassemble frames that span several reads;
- bound its buffer at `HEADER_SIZE + MAX_PAYLOAD`.

## 3. Frame types

A frame is either **plaintext** (no tag, before session keys exist) or
**encrypted** (ChaCha20-Poly1305, section 5.2). Only `HANDSHAKE` is plaintext.

### 3.1 Control (stream 0)

| Value | Name | Enc | Payload |
|-------|------|-----|---------|
| `0x01` | `HANDSHAKE` | no | Section 4.2 |
| `0x02` | `PAIR_CONFIRM` | yes | empty |
| `0x03` | `PAIR_REJECT` | yes | `reason: u16` (error code, section 7) |
| `0x04` | `PING` | yes | `nonce: u64` |
| `0x05` | `PONG` | yes | `nonce: u64` (echo of `PING`) |
| `0x06` | `REKEY` | yes | empty |
| `0x07` | `CLOSE` | yes | `code: u16, reason_len: u16, reason: [reason_len] u8` (UTF-8, `reason_len <= 256`) |

### 3.2 Messaging (stream 1)

| Value | Name | Enc | Payload |
|-------|------|-----|---------|
| `0x10` | `MSG` | yes | Defined in Phase 7 spec |
| `0x11` | `MSG_ACK` | yes | Defined in Phase 7 spec |
| `0x12` | `SYNC_REQUEST` | yes | Defined in Phase 7 spec |
| `0x13` | `SYNC_RESPONSE` | yes | Defined in Phase 7 spec |

V1 Phase 1 uses `MSG` with payload `text_len: u32, text: [text_len] u8` (UTF-8),
until the persistent message format replaces it.

### 3.3 Transfer (stream >= 2)

| Value | Name | Enc | Payload |
|-------|------|-----|---------|
| `0x20` | `TRANSFER_OFFER` | yes | Manifest, defined in Phase 2 spec |
| `0x21` | `TRANSFER_ACCEPT` | yes | Phase 2 |
| `0x22` | `TRANSFER_REJECT` | yes | Phase 2 |
| `0x23` | `CHUNK_REQUEST` | yes | Phase 2 |
| `0x24` | `CHUNK_DATA` | yes | Phase 2 |
| `0x25` | `CHUNK_ACK` | yes | Phase 2 |
| `0x26` | `TRANSFER_CANCEL` | yes | Phase 2 |
| `0x27` | `TRANSFER_COMPLETE` | yes | Phase 2 |
| `0x28` | `TRANSFER_RESUME` | yes | Phase 3 |

Value `0x00` and all unlisted values are invalid in v0.1.
