# 2Link Testing Strategy v0.1

Defines how 2Link is verified: which tests exist, at which level, with which pass
criteria. Tests are defined here **before** the features they cover.

References: [protocol-spec.md](protocol-spec.md) ("spec §x"),
[threat-model.md](threat-model.md) (threat IDs such as `S6`, `F1`).

## 1. Principles

1. **Every threat has a test.** Each threat ID in the threat model maps to at least
   one test in section 4, or is explicitly marked as review-only.
2. **Every bug gets a regression test** before the fix is merged.
3. **Baseline first.** Plain TCP performance is measured before streams, UDP or
   multipath are added, and every later feature is compared against that baseline.
4. **Measured, not asserted.** Performance claims come with method, hardware and raw
   numbers (section 6).
5. **Sanitizers are always on in CI.** A test that only passes without ASan/UBSan
   is a failing test.

## 2. Test levels

| Level | What | Where | Runs |
|-------|------|-------|------|
| Unit | One module in isolation (framing, crypto wrappers, state machines, TLV, file-name sanitizer) | `tests/<module>/`, GoogleTest | Every build, CI |
| Property / fuzz | Parsers and decoders on random and mutated input | `tests/fuzz/`, libFuzzer | CI (60 s per target), nightly (longer) |
| Integration | Two endpoints in one process over loopback TCP: handshake, pairing, messaging, transfer, failure injection | `tests/integration/` | Every build, CI |
| System | Two `2link` processes, then two physical PCs on a LAN | `tests/system/` scripts | Manual / before each milestone |
| Benchmark | Throughput, latency, CPU | `bench/` | Manual, results recorded in `docs/benchmarks/` |

### 2.1 Conventions

- Test names reference threat IDs where relevant: `TEST(PathSanitizer, F1_RejectsDotDot)`.
- Integration tests use a fake clock and an in-memory transport where possible, so
  timeouts (spec §6.5) are tested without sleeping.
- Each fuzz target keeps a seed corpus in `tests/fuzz/corpus/` (or a per-target
  subdirectory). Crashes found by fuzzing are added to the corpus as regression inputs.

## 3. Tooling and CI

| Tool | Purpose | Status |
|------|---------|--------|
| GoogleTest + CTest | Unit and integration tests | In use |
| ASan + UBSan | Memory errors, undefined behaviour (`asan`, `ci` presets) | In use |
| libFuzzer (Clang) | Coverage-guided fuzzing (`fuzz` preset) | In use (frame parser) |
| Fuzz replay driver | Replays corpus and crash files with GCC/MSVC | In use |
| MSVC `/W4 /WX` | Windows build (`msvc` preset) | In use |
| `tc netem` | Delay, loss, reordering, rate limits on Linux | Phase 3 |
| `iperf3` | Raw TCP throughput ceiling | Phase 2 |
| Wireshark / `tcpdump` | Confirm no plaintext on the wire (S1) | Phase 1 |
| Coverage (`gcov` / `llvm-cov`) | Find untested code; no hard threshold | Phase 1 |
| ThreadSanitizer | Data races once the networking core is multi-threaded | Phase 1 |

### 3.1 CI pipeline

| Job | Runner | Checks |
|-----|--------|--------|
| `linux` | Ubuntu 24.04, GCC | Build with `-Werror`, ASan + UBSan, all CTest tests |
| `windows` | Windows 2022, MSVC | Build with `/WX`, all CTest tests |
| `fuzz` | Ubuntu 24.04, Clang | Each fuzz target for 60 s |

Planned: a nightly job that fuzzes each target for 30 minutes and keeps its corpus,
and a TSan job once threads are introduced.

A change is mergeable only when all jobs pass.

## 4. Security tests

One row per threat ID. **Phase** is when the test must exist (before the feature
is called done). Status: `done`, `partial`, `planned`, `review` (verified by code or
design review, no automated test).

### 4.1 Discovery

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| D1 | Forged announcement reuses a trusted peer's name with a foreign key | Integration | Shown as unverified; IK to it fails; trust store unchanged | 1 | planned |
| D2 | Announcement with `DEVICE_ID != BLAKE2b-256(key)` | Unit | Dropped | 1 | planned |
| D3 | Fuzz the announcement parser; malformed TLV corpus; datagram > 512 bytes | Fuzz, unit | No crash; every malformed input dropped | 1 | planned |
| D4 | 10 000 announcements from distinct IDs and sources | Unit | Device table stays at its cap; memory bounded; old entries expire | 1 | planned |
| D5 | — | — | Accepted risk | — | n/a |

### 4.2 Handshake and pairing

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| H1 | Relay attacker runs separate XX handshakes with each side | Integration | The two SAS values differ; neither side stores the attacker key unless confirmed | 1 | planned |
| H1 | SAS known-answer vectors (fixed `h` → expected 6 digits) | Unit | Matches spec §4.5 exactly, incl. zero padding | 1 | done |
| H2 | 3 failed pairings from source A in 10 min, then a 4th from A and one from B | Unit (fake clock) | A refused without handshake, B accepted; A accepted again after 10 min; limiter table capped at 256 sources | 1 | planned |
| H2 | `PAIR` outside the pairing window; window expiry; window after a successful pairing | Unit (fake clock) | Refused outside the window; window closes after 5 min or one success; `RECONNECT` unaffected | 1 | planned |
| H3 | — | Review | UI requires explicit confirm on both sides | 8 | review |
| H4 | Peer reappears with the same name and a new key | Integration | Shown as unknown + identity-change warning; IK refused; old record kept until explicit re-pair | 1 | planned |
| H5 | Unpaired key attempts IK | Integration | Responder closes TCP; no session; no frame sent | 1 | planned |
| H6 | Every handshake failure path | Unit | No bytes written before close; error reported locally only | 1 | done (handshake engine); state machine in 1.5 |
| H7 | Wrong prologue; `kind` changes mid-handshake; IK failure | Unit, integration | Handshake fails; no XX fallback | 1 | unit done; integration in 1.10 |
| H7 | TLV list: unknown optional tag (`0x7F`), unknown critical tag (`0x80`, `0xFF`), duplicate known and unknown tags, missing required tag, truncated value | Unit, fuzz | Optional ignored; every other case rejects the whole list | 1 | done (`fuzz_handshake_payload`) |
| H8 | Replay a captured handshake message | Integration | Handshake fails | 1 | planned |
| H9 | Open many TCP connections that never complete the handshake | Integration (fake clock) | At most 4 `PAIR` handshakes and one `AWAIT_CONFIRM` at a time; extra connections closed; all time out after 10 s; memory bounded | 1 | planned |
| H10 | Two peers connected at once | Integration | Frames from peer A's connection never decrypt under peer B's keys; identity always from the Noise static key | 1 | planned |
| H10 | — | Review | No code path derives identity from name or announcement | 1 | review |

### 4.3 Session and framing

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| S1 | Capture a session with `tcpdump`; search for known plaintext | System | Plaintext absent | 1 | planned |
| S2 | Flip each bit of header and payload of an encrypted frame | Unit | Every flip is fatal and no plaintext is returned; flips that leave `conn_id`, `seq` and `length` intact (payload, type/stream variants) → `DECRYPT_FAILED`, the rest are caught earlier by the parser or the `conn_id`/`seq` checks | 1 | done |
| S3 | Duplicate, skipped and swapped `seq` | Unit | Fatal `REPLAY_DETECTED` | 1 | done |
| S4 | Encrypt N frames with a rekey in the middle; compare `seq` with both CipherState counters | Unit | `seq` == sender counter == receiver counter for every frame; counter not reset by rekey; no (key, nonce) pair repeats; connection closes before counter `2^64-1` | 1 | done |
| S4 | — | Review | No code sets a nonce manually; only the CipherState chooses nonces | 1 | review |
| S5 | Replay a frame from connection A on connection B | Integration | Rejected (`conn_id` mismatch or decrypt failure) | 1 | unit done; integration in 1.10 |
| S6 | Header with `length` above limits, split and unsplit | Unit | Rejected after the header; buffer never exceeds `kMaxFrameSize` | 0 | done |
| S7 | Fuzz the frame parser; random garbage under ASan/UBSan | Fuzz, unit | No crash or sanitizer report; chunking-invariant results | 0 | done |
| S8 | Every (state, frame type) and (stream, frame type) pair from spec §2.2 and §6.3 | Unit | Allowed pairs accepted; all others fatal | 0 / 1 | partial (stream rules done) |
| S9 | — | Review | Ephemeral keys used; session keys zeroed on teardown | 1 | review |
| S10 | Inject a TCP reset mid-transfer | Integration | IK reconnect succeeds; transfer resumes (see R2) | 3 | planned |

### 4.4 File transfer

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| F1 | Malicious name corpus: `../x`, `/etc/passwd`, `C:\x`, `\\host\share`, `CON`, `a/b`, NUL and control chars, empty, 4 KiB long, Unicode tricks | Unit | Every name rejected or reduced to a safe final component inside the download dir | 2 | planned |
| F2 | Receive a file whose name already exists | Unit | Existing file untouched; unique name chosen; temp file renamed only after verification | 2 | planned |
| F3 | Corrupt one chunk in transit; substitute a chunk from another file | Integration | Chunk rejected and re-requested; final BLAKE3 root matches | 2 | planned |
| F4 | Offer a file larger than free space or the size limit | Unit | Offer refused before any write | 2 | planned |
| F5 | Out-of-range chunk index; 9th pending offer, 5th concurrent transfer, unrequested chunk | Unit | Index rejected; offers rejected at quota; unrequested `CHUNK_DATA` fatal | 2 | planned |
| F6 | Modify a partial file on disk, then resume | Integration | Modified chunks detected and re-fetched | 3 | planned |
| F7 | Send `CHUNK_DATA` / `TRANSFER_COMPLETE` for an offer the user has not accepted; user rejects an offer | Unit, integration | Fatal before acceptance; nothing written to disk; rejected offer leaves no file | 2 | planned |
| F8 | Receive a file named `run.sh` / `setup.exe` with executable content | Unit | No execute bit on Linux; Mark of the Web stream on Windows; nothing launched | 2 | planned |
| F8 | — | Review | No code path opens or executes received files | 2 | review |

### 4.5 Local storage

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| L1 | Store, then load with the file made group/other-readable, replaced by a symlink or a directory; store into a group-writable directory; store twice; damage the file | Unit | Stored file `0600` in a `0700` directory; every unsafe case `kInsecurePermissions`; second store `kAlreadyExists` and the original kept; damage `kCorrupt`; on Windows the raw secret never appears in the file | 1 | done |
| L1 | — | Review | Private key only goes through the keystore API; a damaged key is never replaced automatically | 1 | review |
| L2 | Edit the trust store file | Unit | Integrity check fails; store refused | 1 | planned |
| L2 | File permissions after creation | Unit (Linux) | `0600` | 1 | planned |
| L3 | Modify, delete or reorder a message record | Unit | Hash chain verification fails | 7 | planned |
| L4 | — | Review | `sodium_memzero` on every key buffer at teardown | 1 | review |
| L5 | Run integration tests with debug logging; grep logs for key bytes, plaintext markers, SAS | Integration | No match | 1 | planned |

### 4.6 Per-peer resources

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| Q1 | Peer A exceeds each quota in spec §6.6 while peer B chats and transfers | Integration | A's excess refused or back-pressured as specified; A's memory use stays bounded; B's chat latency and transfer unaffected | 2 | planned |
| Q1 | Message larger than 60 KiB; 1 000 messages per second | Unit | Oversized message fatal; flood slowed by back-pressure, not buffered | 1 | planned |
| Q2 | Fill offline storage for one peer | Unit | Cap enforced per peer; other peers' storage unaffected | 7 | planned |

### 4.7 Third-party cryptographic code

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| X1 | Cacophony vectors for `Noise_XX` and `Noise_IK` `25519_ChaChaPoly_BLAKE2b` | Unit | Every handshake and transport ciphertext matches byte for byte, on Linux and MSVC | 1 | done |
| X1 | — | Review | Any change of the pinned noise-c commit is reviewed and reruns the conformance tests | 1 | review |
| X2 | Shim `Rekey()` versus libsodium `REKEY(k)`; counter after rekey; one-sided rekey; old key after rekey | Unit | Keys equal; counter unchanged; one-sided rekey fails decryption; old key fails | 1 | done |
| X3 | Force every noise-c constructor and handshake call to fail through the wrapper | Unit (ASan) | No use-after-free; wrapper holds no pointer after an error | 1 | done |

## 5. Reliability tests

| ID | Scenario | Level | Pass criterion | Phase |
|----|----------|-------|----------------|-------|
| R1 | Kill the receiver at 10 %, 50 %, 99 % of a 1 GiB transfer; restart; resume | Integration, system | File completes; final hash matches; bytes re-sent ≤ one chunk per in-flight request | 3 |
| R2 | Drop the TCP connection (reset, cable pull, Wi-Fi off) mid-transfer | System | IK reconnect and resume without user action; same criteria as R1 | 3 |
| R3 | Sender restarts mid-transfer | Integration | Resume from the persisted bitmap; no verified chunk re-sent | 3 |
| R4 | Crash during chunk write (kill -9 between write and bitmap update) | Integration | On resume the chunk is re-verified, never trusted blindly | 3 |
| R5 | Idle peer disappears | Integration (fake clock) | Detected within `IDLE_TIMEOUT` (45 s); state `CLOSED` | 1 |
| R6 | Both peers connect at once | Integration | Exactly one primary connection survives (spec §6.4) | 1 |
| R7 | Rekey under load: force `REKEY` every 1 000 frames during a transfer | Integration | No decrypt failures; transfer completes | 1 |
| R8 | Messages sent while the peer is offline | Integration | Delivered once after reconnect, in order, no duplicates | 7 |
| R9 | Impairment matrix (5.1) | System | All transfers complete with a correct hash; no crash or hang | 3 |

**"Bytes re-sent"** is measured by counting `CHUNK_DATA` frames per chunk index on
the sender; any verified chunk sent twice fails R1–R3.

### 5.1 Network impairment matrix (`tc netem`)

Applied to the sender's interface, or to a veth pair between two network namespaces
for automated runs.

| Delay | Loss | Extra |
|-------|------|-------|
| 0 ms | 0 % | — (baseline) |
| 20 ms ± 5 ms | 0.1 % | — |
| 100 ms | 1 % | 25 % reordering |
| 20 ms | 5 % | — |
| 0 ms | 0 % | Rate limited to 10 Mbit/s |
| 0 ms | 0 % | Link down for 10 s mid-transfer |

## 6. Performance tests

### 6.1 Method

- **Hardware:** two PCs on a gigabit Ethernet switch, no other traffic. Record CPU
  model, OS, NIC, link speed **and storage throughput (P0)** with every result.
- **Builds:** `release` preset only. Never benchmark sanitizer builds.
- **Repetition:** 5 runs per configuration; report the median and min/max.
- **Storage:** results are committed to `docs/benchmarks/<date>-<topic>.md` with the
  raw numbers and the exact commit hash.

### 6.2 Throughput

| ID | Measurement | Target (V1) | Phase |
|----|-------------|-------------|-------|
| P0 | Storage throughput: sequential read of a 4 GiB file on the sender's source disk, sequential write of 4 GiB to the receiver's download directory (`fio` on Linux, `diskspd` on Windows, page cache bypassed) | Ceiling reference, no target | 2 |
| P1 | `iperf3 -t 30` TCP between the two PCs | Ceiling reference, no target | 2 |
| P2 | 2Link transfer of a 4 GiB random file over the bulk connection, disk to disk | ≥ 80 % of min(P1, P0 read, P0 write) | 2 |
| P3 | Same as P2 from and to a RAM disk | ≥ 85 % of P1 (removes storage from the path) | 2 |
| P4 | Loopback microbenchmark: frame encode + AEAD + parse, one core | Report Gbit/s; must exceed 1 Gbit/s so crypto is not the bottleneck | 1 |
| P5 | CPU utilization during P2 (sender and receiver) | Report; no target in V1 | 2 |

### 6.3 Latency

| ID | Measurement | Target (V1) | Phase |
|----|-------------|-------------|-------|
| L-1 | Chat round-trip (`MSG` → echo), idle link, 1 000 samples | Report p50 / p99 | 1 |
| L-2 | Chat round-trip while a P2 transfer saturates the link | p99 ≤ 50 ms and ≤ idle p99 + 20 ms | 4 |
| L-3 | Same as L-2 but chat and bulk on **one** TCP connection | Report; expected to be much worse (shows head-of-line blocking, justifies spec §6.4) | 4 |
| L-4 | Time from TCP connect to `ESTABLISHED` with IK | Report p50 / p99 | 1 |

L-1 and L-2 timestamps come from one monotonic clock on the sender (round trip), so
the two PCs need no clock synchronization.

### 6.4 Baseline rule

P0–P5 and L-1–L-4 on plain TCP form the **V1 baseline**. The UDP transport (V2) and
multipath must report the same measurements against it, and QUIC is measured in the
same setup as the reference.

## 7. Acceptance tests (V1)

| # | Criterion | Verified by |
|---|-----------|-------------|
| 1 | Two PCs pair securely and authenticate on reconnect | H1, H4, H5, system test of pairing + IK reconnect |
| 2 | Encrypted messages and reliable file transfer | S1, S2, F3, P2 |
| 3 | Interrupted transfers resume without re-sending verified chunks | R1–R4 |
| 4 | Chat stays responsive during bulk transfer; concurrent transfers work | L-2, F5, concurrent-transfer integration test |
| 5 | Offline messages sync after reconnection | R8 |
| 6 | Measured performance on gigabit Ethernet | P0–P5 report |
| 7 | All automated correctness and robustness tests pass | CI green on all jobs |

## 8. Definition of done (per feature)

A feature is done when:

1. Its rows in sections 4–6 exist as tests and pass, or are marked `review` with the
   review recorded in the pull request.
2. CI passes on Linux (sanitizers), Windows (MSVC) and fuzzing.
3. Every new parser of remote input has a fuzz target and a seed corpus.
4. The threat model and this document are updated if the feature adds a threat or
   changes a limit.
