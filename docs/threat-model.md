# 2Link Threat Model v0.1

Scope: V1, two PCs on the same LAN over direct TCP, as defined in
[protocol-spec.md](protocol-spec.md). Section references like "spec §4.5" point
there.

## 1. System overview

```
 PC1                                                   PC2
+-----------------------+                     +-----------------------+
| CLI / UI              |                     | CLI / UI              |
| session, transfer,    |   primary (TCP)     | session, transfer,    |
| storage               |<===================>| storage               |
| keystore, trust store |   bulk (TCP)        | keystore, trust store |
| file system           |<===================>| file system           |
+-----------------------+   discovery (UDP)   +-----------------------+
            ^ ^ ^ ^ ^ ^   <- - - - - - - - ->   ^ ^ ^ ^ ^ ^
                      shared LAN: other hosts, attacker
```

## 2. Assets

| ID | Asset | Property to protect |
|----|-------|---------------------|
| A1 | Static private key | Confidentiality; never leaves the device |
| A2 | Trust store (pinned peer keys) | Integrity |
| A3 | Session keys | Confidentiality; erased when the session ends |
| A4 | Message contents | Confidentiality, integrity, authenticity |
| A5 | File contents and transfer metadata (names, sizes, hashes) | Confidentiality, integrity, authenticity |
| A6 | Local file system outside the download directory | Integrity (no writes outside it) |
| A7 | Message log and transfer state on disk | Integrity; tamper evidence |
| A8 | Availability of the app and host (CPU, memory, disk) | Availability |
| A9 | Device metadata (name, device ID, online status) | Limited: treated as public on the LAN |

## 3. Threat actors

| ID | Actor | Capabilities |
|----|-------|--------------|
| T1 | Passive LAN attacker | Reads all LAN traffic, including broadcasts |
| T2 | Active LAN attacker | T1 plus injecting, dropping, modifying, replaying and reordering packets; ARP spoofing; opening TCP connections; sending forged discovery announcements |
| T3 | Man-in-the-middle during pairing | T2, positioned between both PCs during first pairing |
| T4 | Malicious unpaired device | Runs a modified 2Link client; tries to pair, connect or crash peers |
| T5 | Malicious or compromised paired device | Holds valid keys; sends well-authenticated but hostile frames, files and messages |
| T6 | Resource-exhaustion attacker | T2 or T4 aiming to exhaust memory, CPU, disk, sockets or pairing attempts |
| T7 | Local unprivileged user or process on the same PC | Reads world-readable files; cannot read other users' keystore entries |

## 4. Trust boundaries

| ID | Boundary | Crosses it |
|----|----------|------------|
| B1 | Network → process | Every TCP byte and UDP datagram. All input is hostile until parsed, bounds-checked and (after the handshake) authenticated. |
| B2 | Unauthenticated → authenticated | The Noise handshake. Before it completes, nothing a peer says is trusted. |
| B3 | Authenticated → trusted | User SAS confirmation (XX) or a pinned key (IK). An authenticated but unpaired key is not trusted. |
| B4 | Trusted peer → local resources | Peer-supplied file names, sizes, chunk counts, message sizes. A trusted peer can still be malicious (T5). |
| B5 | Process → disk / keystore | Private key, trust store, message log, partial files. |

## 5. Assumptions

- The operating system, the keystore (libsecret, DPAPI) and the user account
  running 2Link are not compromised.
- libsodium, the Noise library and BLAKE3 are correctly implemented.
- Users actually compare the SAS on both screens before confirming.
- The CSPRNG (libsodium `randombytes`) is sound.
- First pairing happens with both users physically able to see both screens, or
  using a trusted channel to compare codes.

## 6. Threats and mitigations

Each threat lists the actor, the mitigation, and how it will be verified. The
"Verified by" column becomes concrete test cases in the testing strategy (task 0.6).
Status is `spec` (designed, not implemented) for all of v0.1.

### 6.1 Discovery

| ID | Threat | Actor | Mitigation | Verified by |
|----|--------|-------|------------|-------------|
| D1 | Forged announcement impersonates a known peer | T2, T4 | Discovery never grants trust (spec §8). A paired device is trusted only after IK against the pinned key succeeds. | Integration test: forged announcement with a trusted name and a foreign key is shown as unverified; IK against it fails |
| D2 | Announcement with mismatched `DEVICE_ID` and key | T2 | Receiver drops it unless `DEVICE_ID == BLAKE2b-256(key)` | Unit test |
| D3 | Malformed or oversized datagram crashes the parser | T2 | 512-byte limit; strict TLV parsing; fuzzing | Fuzz target, unit tests |
| D4 | Announcement flood exhausts memory or the device list | T6 | Bounded device table with expiry; per-source rate limit | Unit test with a flood |
| D5 | Passive attacker learns device names and presence | T1 | Accepted: announcements are public by design | — |

### 6.2 Handshake and pairing

| ID | Threat | Actor | Mitigation | Verified by |
|----|--------|-------|------------|-------------|
| H1 | MITM during first pairing | T3 | Noise XX + 6-digit SAS from the handshake hash. Two separate handshakes produce different codes (spec §4.5). | Integration test: relay attacker yields mismatched SAS |
| H2 | Attacker guesses the SAS | T3 | One guess per attempt (~2^-20); fresh handshake per attempt; 3 failures in 10 min → 10 min lockout (spec §4.6) | Unit test of the rate limiter |
| H3 | User confirms without comparing | T3 | Residual risk (section 8). UI shows the code prominently and requires an explicit action on both sides. | Manual / UI review |
| H4 | Changed key passed off as a known peer | T2, T4 | `device_id` is derived from the key, so a new key is an unknown device. Trust never carries over; the UI warns on a name match; trust only after explicit re-pairing (spec §4.8). | Integration test: same name, new key → unverified + warning; IK refused |
| H5 | Unpaired device connects with IK | T4 | Responder requires the initiator key in its trust store; otherwise TCP close (spec §4.8) | Integration test |
| H6 | Forged error during handshake (oracle, downgrade) | T2 | No error frames before keys exist; connection is just closed (spec §7.1) | Unit test: handshake state never emits a plaintext error |
| H7 | Version or pattern downgrade | T2 | Single version; prologue `"2LINK/1"` binds the transcript; `kind` must stay constant; no IK → XX fallback | Unit tests |
| H8 | Handshake replay | T2 | Fresh ephemeral keys per handshake; replayed messages fail Noise | Integration test |
| H9 | Many half-open handshakes exhaust resources | T6 | `HANDSHAKE_TIMEOUT` 10 s; cap on concurrent handshakes; one pairing at a time | Load test |
| H10 | Key confusion between devices | T5 | Keys are per connection and direction; peer identity is the authenticated Noise static key, never a name or announced ID | Code review, unit test |

### 6.3 Session and framing

| ID | Threat | Actor | Mitigation | Verified by |
|----|--------|-------|------------|-------------|
| S1 | Eavesdropping on messages or files | T1 | ChaCha20-Poly1305 with Noise-derived keys | Packet capture shows no plaintext |
| S2 | Modifying payload or header fields | T2 | AEAD with the full header as associated data (spec §5.2) | Unit test: flip each header and payload byte → `DECRYPT_FAILED` |
| S3 | Replay, drop or reorder of frames | T2 | Strict `seq == expected` over TCP (spec §5.3) | Unit tests: duplicate, gap, reorder → fatal |
| S4 | Nonce reuse | Implementation bug | Nonces come only from the Noise CipherState counter, which advances once per frame and never resets (not even on rekey); `seq` must equal it; keys per direction; counter `2^64-1` never reached | Unit tests, code review |
| S5 | Frames spliced from another connection | T2 | `conn_id` in authenticated header; separate keys per connection | Unit test |
| S6 | Oversized `length` causes huge allocation | T2, T5 | Header validated before allocation; `MAX_PAYLOAD` 512 KiB; parser buffer bounded (spec §2.1, §2.4) | Unit tests, fuzzing |
| S7 | Malformed frames trigger memory bugs | T2, T5 | Bounds-checked parsing; ASan/UBSan in CI; fuzzing the frame parser | Fuzz target, sanitizer CI |
| S8 | Frame valid in the wrong state or stream | T5 | Per-state and per-stream allowed-type tables (spec §2.2, §6.3) | Unit tests per table entry |
| S9 | Long-lived key compromise exposes all traffic | T1 + later key theft | Ephemeral DH gives forward secrecy; periodic rekey limits per-key volume | Design review |
| S10 | TCP reset or injected FIN kills the session | T2 | Accepted for V1; reconnect with IK and resume transfers (Phase 3) | Reliability tests |

### 6.4 File transfer

| ID | Threat | Actor | Mitigation | Verified by |
|----|--------|-------|------------|-------------|
| F1 | Path traversal via file name (`../`, absolute paths, drive letters, UNC) | T5 | Use only the final name component; reject separators, `..`, control characters, reserved Windows names; write only inside the download directory | Unit tests with a malicious-name corpus |
| F2 | Overwriting existing files | T5 | Never overwrite; pick a unique name; write to a temp file and rename after verification | Unit test |
| F3 | Corrupted or substituted chunks | T2, T5 | BLAKE3 per chunk; Merkle root sent inside the authenticated session (Phase 2) | Unit test: bad chunk rejected and re-requested |
| F4 | Disk exhaustion via huge declared size | T5, T6 | Check free space before accepting; per-transfer and total size limits; user accepts offers | Unit test |
| F5 | Unbounded transfers or chunk requests | T5, T6 | Cap concurrent transfers and in-flight chunks; validate chunk index against the manifest | Unit tests |
| F6 | Tampered partial file or resume state on disk | T7 | Re-verify chunk hashes on resume; restrictive file permissions | Reliability test |

### 6.5 Local storage

| ID | Threat | Actor | Mitigation | Verified by |
|----|--------|-------|------------|-------------|
| L1 | Private key theft from disk | T7 | Stored in the OS keystore, never in a plain file | Code review |
| L2 | Trust store tampering (pinning an attacker key) | T7 | File permissions `0600` / user-only ACL; the trust store is integrity-checked with a key from the keystore | Unit test |
| L3 | Message log tampering | T7 | Hash-chained records give tamper evidence only (Phase 7) | Unit test |
| L4 | Keys left in memory or swap | T7 | `sodium_memzero` on session teardown; `sodium_mlock` for long-term keys where supported | Code review |
| L5 | Secrets in logs | Implementation bug | Never log keys, plaintext, or SAS values; log device IDs in display form only | Code review, log-grep test |

## 7. Out of scope for V1

| Item | Reason |
|------|--------|
| Attackers with root/admin or physical access to an endpoint | Can read the keystore and memory; no endpoint software defends this |
| Compromised OS, keystore or cryptographic libraries | Assumption (section 5) |
| Traffic analysis (timing, sizes, who talks to whom) | No padding or cover traffic in V1 |
| Hiding device presence on the LAN | Discovery is public by design (D5) |
| Internet attackers, NAT traversal, relays | V2 / V3 |
| Group messaging, multi-device accounts | Non-goals |
| Post-quantum security | Curve25519 only; revisit when vetted PQ Noise patterns are available |
| Denial of service by an on-path attacker dropping all traffic | Cannot be prevented; only detected (idle timeout) |
| Side channels in cryptographic primitives | Delegated to libsodium |

## 8. Residual risks

| Risk | Impact | Why accepted / follow-up |
|------|--------|--------------------------|
| User confirms the SAS without comparing (H3) | MITM succeeds at pairing | Usability limit; consider a QR fingerprint or longer code in v0.2 |
| 6-digit SAS (~20 bits) | 1 in 10^6 MITM success per attempt | One guess per attempt plus rate limiting; longer code later |
| Malicious paired device (T5) | Can send hostile but well-formed content | Mitigated by input validation (F1–F5, S6–S8), not by crypto. Users should only pair devices they control. |
| Injected TCP resets (S10) | Sessions drop | Fast IK reconnect and transfer resume |
| Hash chain only gives tamper evidence (L3) | A compromised endpoint can delete messages | Documented limitation |
| Device names leak on the LAN (D5) | Presence and naming visible | Users choose neutral names |

## 9. Maintenance

Update this document when:

- the protocol spec changes version;
- a new transport (UDP, relay) or feature (multipath, sync) is added;
- a security bug is found: add the threat, its mitigation and a regression test.

Each threat ID stays stable so tests and commits can reference it (e.g. `test: F1
path traversal corpus`).
