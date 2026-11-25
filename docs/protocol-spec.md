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

## 4. Identity, handshake and pairing

### 4.1 Device identity

- Each installation generates one persistent Curve25519 static key pair. The private
  key MUST stay on the device, in the OS secure keystore (libsecret, Windows DPAPI).
- `device_id = BLAKE2b-256(static_public_key)` (32 bytes). A changed key gives a
  changed `device_id`.
- Display form: the first 8 bytes of `device_id` as lowercase hex in four groups of
  four characters, e.g. `3fa1-09bc-77de-0142`.

### 4.2 Handshake framing

Noise messages travel in `HANDSHAKE` frames on stream 0, one Noise message per
frame. `seq` is `0, 1, 2` for successive handshake frames in the connection,
counted across both directions. The payload is:

```
kind: u8 | noise_message: [length - 1] u8
```

| `kind` | Meaning | Noise pattern |
|--------|---------|---------------|
| `0x01` | `PAIR` | `Noise_XX_25519_ChaChaPoly_BLAKE2b` |
| `0x02` | `RECONNECT` | `Noise_IK_25519_ChaChaPoly_BLAKE2b` |

Every `HANDSHAKE` frame in a connection MUST carry the same `kind`.

**Prologue.** Both patterns use the prologue `"2LINK/1"` (7 ASCII bytes). A peer
using a different prologue fails the handshake.

### 4.3 Handshake payloads

The Noise payloads that are encrypted (XX messages 2 and 3, IK messages 1 and 2)
carry a TLV list. XX message 1 carries an empty payload.

```
tag: u8 | len: u16 | value: [len] u8     (repeated)
```

| Tag | Name | Value | Rule |
|-----|------|-------|------|
| `0x01` | `DEVICE_NAME` | UTF-8, 1..64 bytes | Required |
| `0x02` | `ROLE` | u8: `0` primary, `1` bulk | Required |
| `0x03` | `FEATURES` | u32 bitmask, `0` in v0.1 | Optional |

- A duplicate tag, a missing required tag, or a malformed value is fatal.
- Unknown tags MUST be ignored, so that later versions can add fields.
- `ROLE = bulk` is only valid with `kind = RECONNECT` (section 6.4).

### 4.4 First pairing: Noise XX

```
-> e
<- e, ee, s, es       payload: TLV (responder identity)
-> s, se              payload: TLV (initiator identity)
```

After message 3 both sides have the authenticated remote static key and the
handshake hash `h`. The connection enters `AWAIT_CONFIRM` (section 6).

### 4.5 Short authentication string (SAS)

```
d   = BLAKE2b-256("2link sas v1" || h)
n   = (first 5 bytes of d as big-endian u40) mod 1 000 000
SAS = n as 6 decimal digits, zero-padded, shown as "123 456"
```

- Both devices display the SAS. Each user compares the two screens and confirms or
  rejects on their own device.
- Confirming sends `PAIR_CONFIRM`. Rejecting sends `PAIR_REJECT` with code
  `PAIRING_REJECTED`, then `CLOSE`.
- Pairing succeeds only when a side has both confirmed locally **and** received the
  peer's `PAIR_CONFIRM`. Then each side stores the peer record (section 4.7).
- No frame other than `PAIR_CONFIRM`, `PAIR_REJECT`, `PING`, `PONG` and `CLOSE` is
  allowed before pairing succeeds.
- The 40-bit reduction keeps the modulo bias below 2^-20.

The SAS is a verification code, not a password. A man-in-the-middle must run two
separate handshakes, which produce two different codes, so the mismatch is visible.
An attacker gets one guess (about 2^-20) per pairing attempt.

### 4.6 Pairing limits

- At most one pairing attempt is in progress per device at a time.
- Each attempt uses a fresh XX handshake; a SAS is never reused.
- The user must decide within `PAIR_TIMEOUT` (120 s) or the attempt fails with
  `PAIRING_TIMEOUT`.
- After 3 failed attempts within 10 minutes, a device refuses new pairing attempts
  for 10 minutes. It closes those TCP connections without a handshake.

### 4.7 Trust store

After successful pairing each side stores, per peer:

| Field | Content |
|-------|---------|
| `device_id` | 32 bytes |
| `name` | From `DEVICE_NAME` |
| `static_public_key` | 32 bytes, pinned |
| `first_paired_at` | UTC timestamp |
| `trust` | `verified` |

### 4.8 Reconnection: Noise IK

```
<- s                  (pre-known: the pinned responder key)
...
-> e, es, s, ss       payload: TLV (initiator identity)
<- e, ee, se          payload: TLV (responder identity)
```

- The initiator only uses `RECONNECT` with a peer in its trust store.
- The responder MUST look up the initiator's static key in its trust store. If the
  key is absent it closes with `UNKNOWN_PEER`.
- If a known `device_id` presents a different static key (for example a peer found by
  discovery with a matching name), the connection is refused with `IDENTITY_CHANGED`.
  It stays refused until the user explicitly re-pairs with XX.
- There is no automatic fallback from IK to XX.
- On success the connection enters `ESTABLISHED` with no user interaction.
