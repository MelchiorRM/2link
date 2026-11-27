# 2Link Protocol Specification v0.1

Status: **frozen** (2026-11-27). Applies to protocol version `1` (V1: LAN, direct
TCP). The Noise library proof-of-concept confirmed sections 4 and 5
(`poc/noise-c/RESULTS.md`). Changes from here on go into v0.2.

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
| `MAX_HANDSHAKE_PAYLOAD` | 65 535 bytes (`kind` byte + Noise message) |

- A receiver MUST validate the full header before reading or allocating for the
  payload. A `length` above the limit for the frame type is fatal.
- An encrypted frame's `length` MUST be at least `AEAD_TAG_SIZE` and at most
  `MAX_PAYLOAD`.
- A `HANDSHAKE` frame's `length` MUST be at least 1 and at most
  `MAX_HANDSHAKE_PAYLOAD`, so a Noise message is at most 65 534 bytes (section 4.2).
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

**File acceptance.** Payload formats come in Phase 2, but these rules are fixed now:

- A transfer starts only after the receiving user explicitly accepts its
  `TRANSFER_OFFER`. V1 has no automatic acceptance.
- Any transfer frame other than `TRANSFER_OFFER` or `TRANSFER_CANCEL` for a transfer
  the receiver has not accepted is fatal (`PROTOCOL_ERROR`).
- Received files MUST NOT be opened or executed automatically. They are written
  without execute permission, and on Windows SHOULD carry the "downloaded from
  another computer" zone marker (Mark of the Web).

Value `0x00` and all unlisted values are invalid in v0.1.

## 4. Identity, handshake and pairing

### 4.1 Device identity

- Each installation generates one persistent Curve25519 static key pair. The private
  key MUST stay on the device, in the OS secure keystore (libsecret, Windows DPAPI).
- `device_id = BLAKE2b-256(static_public_key)` (32 bytes). A changed key gives a
  changed `device_id`.
- The full 32-byte `device_id` is the device's identity. Storage, lookups,
  comparisons and tie-breaks (section 6.4) MUST use all 32 bytes.
- Display form: the first 8 bytes of `device_id` as lowercase hex in four groups of
  four characters, e.g. `3fa1-09bc-77de-0142`. It is only a short label for people
  and logs; it MUST NOT be used to identify, look up or trust a device.

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

The cipher suite (Curve25519, ChaCha20-Poly1305, BLAKE2b) is fixed for protocol
version `1`. The proof-of-concept matched it byte for byte against the Cacophony
reference vectors for both patterns.

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

**Criticality.** The high bit of the tag (`0x80`) marks a **critical** field:

| Tag range | Kind | Unknown to the receiver |
|-----------|------|-------------------------|
| `0x00`–`0x7F` | Optional | MUST be ignored |
| `0x80`–`0xFF` | Critical | Fatal: the receiver MUST reject the whole TLV list |

All v0.1 tags are below `0x80`. A later version that adds a field a peer must not
silently skip (for example one that changes security behaviour) gives it a tag in
`0x80`–`0xFF`.

- A duplicate tag (known or unknown), a missing required tag, or a malformed value
  is fatal.
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

### 4.6 Pairing window and limits

**Pairing window.**

- A device accepts incoming `PAIR` handshakes only while its user has explicitly
  opened a local pairing window (for example `2link pair --listen`).
- The window closes after `PAIR_WINDOW` (5 min), after one successful pairing, or
  when the user closes it, whichever comes first.
- Outside the window, a `PAIR` handshake is refused: the TCP connection is closed
  after the first `HANDSHAKE` frame, with no reply. `RECONNECT` from trusted peers
  is not affected.
- Starting an outgoing pairing is always an explicit user action, never automatic
  (for example, never triggered by discovery).

**Bounded concurrency.**

- At most one pairing per device is in `AWAIT_CONFIRM` at a time.
- At most `MAX_PAIR_HANDSHAKES` (4) `PAIR` connections are in `HANDSHAKING` at a
  time. Further `PAIR` connections are closed without a reply.
- Each attempt uses a fresh XX handshake; a SAS is never reused.
- The user must decide within `PAIR_TIMEOUT` (120 s) or the attempt fails with
  `PAIRING_TIMEOUT`.

**Per-source rate limiting.**

- The source of an attempt is the remote IP address.
- An attempt fails if the SAS is rejected, the decision times out, the handshake
  fails, or the connection closes before pairing succeeds.
- After `PAIR_FAIL_LIMIT` (3) failed attempts from one source within
  `PAIR_FAIL_PERIOD` (10 min), new `PAIR` attempts from that source are refused for
  `PAIR_BLOCK` (10 min) (`RATE_LIMITED`, local).
- The limiter state is bounded to `PAIR_SOURCE_TABLE` (256) sources; the
  least recently seen entry is evicted first.
- There is no global lockout: failures from one source never block pairing from
  another.

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
- Because `device_id` is derived from the static key, a peer whose key changed shows
  up as an **unknown device**, never as a known one with a new key. Trust MUST NOT
  carry over. If an unknown device announces the same name as a trusted peer, the
  implementation SHOULD warn of a possible identity change (`IDENTITY_CHANGED`,
  local only). The new key is trusted only after the user explicitly re-pairs with
  XX, which replaces the old record.
- If the responder's key changed, IK fails cryptographically on the responder, which
  closes the TCP connection. The initiator reports a handshake failure.
- There is no automatic fallback from IK to XX.
- On success the connection enters `ESTABLISHED` with no user interaction.

## 5. Session layer

### 5.1 Session keys

When the handshake completes, Noise `Split()` gives two CipherStates:

| CipherState | Direction |
|-------------|-----------|
| `c1` | initiator → responder |
| `c2` | responder → initiator |

Each side encrypts with its sending CipherState and decrypts with its receiving one.
Keys are never reused across directions or connections.

The Noise implementation (the Noise library plus 2Link's own shim) MUST provide
the standard CipherState operations `EncryptWithAd`, `DecryptWithAd` and `Rekey`,
and expose the remote static key and the handshake hash. Explicit nonce control
(`SetNonce`) is **not** required.

`Rekey` MUST follow the Noise definition exactly:
`REKEY(k) = first 32 bytes of ENCRYPT(k, 2^64-1, "", zeros[32])`, leaving the
counter `n` unchanged (section 5.4).

### 5.2 Frame encryption

Every frame except `HANDSHAKE` is encrypted with ChaCha20-Poly1305:

```
nonce      = the CipherState's internal counter n (standard Noise behaviour)
ad         = the 28-byte frame header, as sent
payload    = ciphertext || tag (16 bytes)
length     = plaintext_length + 16
```

- 2Link never chooses nonces itself. Each `EncryptWithAd` / `DecryptWithAd`
  advances the CipherState counter by exactly one.
- The sender sets `seq` to the counter value of its sending CipherState, i.e. the
  number of encrypted frames it has already sent on this connection. Because TCP
  delivers in order, the receiver's counter equals `seq` of the next valid frame.

- The header, including `length`, is authenticated as associated data, so any change
  to `type`, `stream_id`, `conn_id`, `seq` or `length` makes decryption fail.
- The sender sets `length` before encrypting.
- A decryption failure is fatal (`DECRYPT_FAILED`). The plaintext MUST NOT be used.

### 5.3 Sequence numbers and replay protection

- `seq` of encrypted frames starts at `0` in each direction and increases by exactly
  `1` per frame, mirroring the CipherState counter. It is independent of the
  handshake frame counter.
- Over TCP the receiver MUST check `seq == expected_seq` (its receiving counter)
  **before** decrypting. A duplicate, gap or reordering is fatal
  (`REPLAY_DETECTED`). A frame that slipped past this check would still fail
  decryption, because its nonce would not match.
- Counter value `2^64 - 1` is reserved by Noise; a connection MUST close before
  reaching it.
- V2 (UDP) cannot rely on an implicit in-order counter. It will need explicit
  per-frame nonces and a sliding replay window (section 10).

### 5.4 Rekeying

- A sender MUST rekey its sending direction after `REKEY_FRAMES` (2^24) frames or
  `REKEY_INTERVAL` (1 hour) under one key, whichever comes first. It MAY rekey earlier.
- To rekey, the sender sends `REKEY` (encrypted with the current key), then applies
  Noise `Rekey()` to its sending CipherState. Frames after `REKEY` use the new key.
- On decrypting `REKEY`, the receiver applies `Rekey()` to its receiving CipherState.
- `seq` keeps counting across rekeys and does not reset. Noise `Rekey()` changes the
  key but leaves the counter unchanged, so `seq` and the counter stay equal.
- Each direction rekeys independently.

## 6. Connection state machine

### 6.1 States

| State | Meaning |
|-------|---------|
| `CONNECTING` | TCP connect in progress (initiator only) |
| `HANDSHAKING` | Exchanging `HANDSHAKE` frames |
| `AWAIT_CONFIRM` | XX done; waiting for both users to confirm the SAS |
| `ESTABLISHED` | Authenticated and trusted; application traffic allowed |
| `CLOSING` | `CLOSE` sent or received; draining |
| `CLOSED` | Terminal |

### 6.2 Transitions

| From | Event | To |
|------|-------|----|
| `CONNECTING` | TCP connected | `HANDSHAKING` |
| `CONNECTING` | TCP failure or timeout | `CLOSED` |
| (responder) | TCP accepted | `HANDSHAKING` |
| `HANDSHAKING` | XX complete | `AWAIT_CONFIRM` |
| `HANDSHAKING` | IK complete | `ESTABLISHED` |
| `HANDSHAKING` | Handshake error or `HANDSHAKE_TIMEOUT` | `CLOSED` (TCP close, no frame) |
| `AWAIT_CONFIRM` | Local confirm and `PAIR_CONFIRM` received | `ESTABLISHED` (peer stored) |
| `AWAIT_CONFIRM` | Local reject, `PAIR_REJECT` received, or `PAIR_TIMEOUT` | `CLOSING` |
| `ESTABLISHED` | Local close or fatal error | `CLOSING` (send `CLOSE`) |
| any keyed state | `CLOSE` received | `CLOSED` |
| `CLOSING` | `CLOSE` sent and flushed, or 1 s elapsed | `CLOSED` |
| any | TCP connection lost | `CLOSED` |

### 6.3 Frames allowed per state

| State | Allowed received types |
|-------|------------------------|
| `HANDSHAKING` | `HANDSHAKE` |
| `AWAIT_CONFIRM` | `PAIR_CONFIRM`, `PAIR_REJECT`, `PING`, `PONG`, `CLOSE` |
| `ESTABLISHED` | All types except `HANDSHAKE`, `PAIR_CONFIRM`, `PAIR_REJECT`, subject to section 6.4 |
| `CLOSING` | `CLOSE` (others are discarded) |

Any other frame is fatal (`PROTOCOL_ERROR`).

### 6.4 Primary and bulk connections

V1 uses up to two TCP connections per paired peer:

| | Primary | Bulk |
|-|---------|------|
| Handshake | XX (pairing) or IK | IK only |
| `ROLE` | `0` | `1` |
| Streams | 0 (control), 1 (messaging) | 0 (`PING`, `PONG`, `REKEY`, `CLOSE` only), transfer streams |
| Opened | First | Only while a primary connection to the same `device_id` is `ESTABLISHED` |

- Each connection runs its own handshake and has its own keys and `conn_id`.
- A bulk connection without an established primary to the same peer is closed.
- At most one primary and one bulk connection per peer. If both peers dial at once,
  the connection whose initiator has the lexicographically lower `device_id` is
  kept; the other is closed with `DUPLICATE_CONNECTION`.
- Closing the primary connection closes the bulk connection.

### 6.5 Timers

| Timer | Value | Effect |
|-------|-------|--------|
| `CONNECT_TIMEOUT` | 5 s | TCP connect fails |
| `HANDSHAKE_TIMEOUT` | 10 s | Handshake fails |
| `PAIR_TIMEOUT` | 120 s | Pairing fails (`PAIRING_TIMEOUT`) |
| `PAIR_WINDOW` | 5 min | Local pairing window closes (section 4.6) |
| `KEEPALIVE_INTERVAL` | 15 s | Send `PING` after this long without sending |
| `IDLE_TIMEOUT` | 45 s | Close (`TIMEOUT`) after this long without receiving |
| `CLOSE_LINGER` | 1 s | Maximum drain time in `CLOSING` |

### 6.6 Per-peer resource limits

Every limit below applies **per paired peer** (`device_id`), on top of global
limits, so one peer cannot exhaust resources needed for others. Values are v0.1
defaults and are finalized in the Phase 2 (transfer) and Phase 7 (messaging) specs.

| Resource | Default limit | On excess |
|----------|---------------|-----------|
| Transfer offers awaiting a user decision | 8 | New offer rejected (`TRANSFER_REJECT`) |
| Concurrent accepted transfers | 4 | New offer rejected |
| In-flight chunks per transfer (requested, not yet received) | 8 (2 MiB) | Receiver does not request more |
| Unrequested `CHUNK_DATA` | 0 | Fatal (`PROTOCOL_ERROR`) |
| Message size | 64 KiB of text | Fatal (`PROTOCOL_ERROR`) |
| Incoming message rate | 50 per second | Back-pressure: the receiver stops reading the socket |
| Stored offline messages for the peer | 10 000 or 64 MiB | Oldest undelivered kept; sender told to retry (Phase 7) |

Excess traffic is handled by refusing or by back-pressure, never by unbounded
buffering.

## 7. Errors

### 7.1 Reporting rules

- **Before session keys exist** (`CONNECTING`, `HANDSHAKING`) errors are never sent
  on the wire; the TCP connection is simply closed. Unauthenticated error frames
  could be forged and would give an attacker an oracle.
- **With session keys**, the side detecting the error sends an encrypted `CLOSE`
  with the error code, then closes the TCP connection. The receiver of `CLOSE` does
  not reply.
- Codes marked *local* are only logged or shown to the user, never sent.
- A received unknown code is treated as `PROTOCOL_ERROR`.

### 7.2 Error codes

| Code | Name | Meaning |
|------|------|---------|
| `0x0000` | `NO_ERROR` | Normal close |
| `0x0001` | `PROTOCOL_ERROR` | Malformed frame, wrong state, bad field |
| `0x0002` | `UNSUPPORTED_VERSION` | `version` is not `1` (local) |
| `0x0003` | `FRAME_TOO_LARGE` | `length` over the limit |
| `0x0004` | `DECRYPT_FAILED` | AEAD authentication failed |
| `0x0005` | `REPLAY_DETECTED` | Unexpected `seq` |
| `0x0006` | `HANDSHAKE_FAILED` | Noise handshake failed (local) |
| `0x0007` | `UNKNOWN_PEER` | IK from a key not in the trust store (local) |
| `0x0008` | `IDENTITY_CHANGED` | Possible key change of a known peer (local) |
| `0x0009` | `PAIRING_REJECTED` | A user rejected the SAS |
| `0x000A` | `PAIRING_TIMEOUT` | No SAS decision in time |
| `0x000B` | `RATE_LIMITED` | Pairing attempts throttled (local) |
| `0x000C` | `TIMEOUT` | Idle timeout |
| `0x000D` | `DUPLICATE_CONNECTION` | Losing side of a simultaneous connect |
| `0x000E` | `INVALID_STREAM` | Frame type not valid on its stream or connection role |
| `0x000F` | `INTERNAL_ERROR` | Local failure |

## 8. Discovery (provisional)

Discovery finds devices; it never establishes trust. Announcements are plaintext
and unauthenticated, so anyone on the LAN can forge them.

### 8.1 Announcement

Sent by UDP broadcast to port `DISCOVERY_PORT` on startup and every 5 s.

```
magic: "2LNK" (4 bytes) | version: u8 = 1 | type: u8 = 0x01 (ANNOUNCE) | TLV list
```

The TLV list uses the encoding of section 4.3:

| Tag | Name | Value | Rule |
|-----|------|-------|------|
| `0x01` | `DEVICE_NAME` | UTF-8, 1..64 bytes | Required |
| `0x10` | `DEVICE_ID` | 32 bytes | Required |
| `0x11` | `STATIC_PUBLIC_KEY` | 32 bytes | Required |
| `0x12` | `TCP_PORT` | u16 | Required |

- The whole datagram MUST be at most 512 bytes.
- A receiver MUST drop announcements with a bad magic, version, type or TLV list
  (including an unknown critical tag, section 4.3), or where
  `DEVICE_ID != BLAKE2b-256(STATIC_PUBLIC_KEY)`.
- A device whose key is in the trust store is shown as *paired*, but is only trusted
  once an IK handshake against the pinned key succeeds.
- Every other device is shown as *unverified* until paired with XX.

mDNS may replace UDP broadcast in a later version.

## 9. Constants

| Name | Value |
|------|-------|
| Protocol version | `1` |
| `HEADER_SIZE` | 28 bytes |
| `MAX_PAYLOAD` | 524 288 bytes |
| `MAX_HANDSHAKE_PAYLOAD` | 65 535 bytes |
| `AEAD_TAG_SIZE` | 16 bytes |
| Noise prologue | `"2LINK/1"` |
| `REKEY_FRAMES` | 2^24 |
| `REKEY_INTERVAL` | 3600 s |
| `DEFAULT_TCP_PORT` | 47821 |
| `DISCOVERY_PORT` | 47820 (UDP) |
| Timers | Section 6.5 |
| Pairing limits | Section 4.6 (`MAX_PAIR_HANDSHAKES` 4, `PAIR_FAIL_LIMIT` 3 per 10 min, `PAIR_BLOCK` 10 min, `PAIR_SOURCE_TABLE` 256) |

## 10. Open questions for v0.2

- Payload formats for messaging (Phase 7) and transfer (Phases 2–3).
- Flow control and priority between transfer streams on the bulk connection (Phase 4).
- Replay window, explicit per-frame nonces and connection migration for the UDP
  transport (V2).
- Longer verification codes or QR fingerprints instead of the 6-digit SAS.

## 11. Resolved for v0.1

- **Noise library (2026-11-27):** noise-c @ `cfe2541` with the libsodium backend,
  a 2Link `Rekey()` shim and a 2Link CMake build. It passes every section 4–5
  requirement on Linux (GCC, ASan/UBSan) and Windows/MSVC. Details and evidence:
  `poc/noise-c/RESULTS.md`.
