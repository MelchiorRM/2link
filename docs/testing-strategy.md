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
| H1 | SAS known-answer vectors (fixed `h` → expected 6 digits) | Unit | Matches spec §4.5 exactly, incl. zero padding | 1 | planned |
| H2 | 3 failed pairings in 10 min, then a 4th attempt | Unit (fake clock) | 4th refused without handshake; accepted again after 10 min | 1 | planned |
| H3 | — | Review | UI requires explicit confirm on both sides | 8 | review |
| H4 | Peer reappears with the same name and a new key | Integration | Shown as unknown + identity-change warning; IK refused; old record kept until explicit re-pair | 1 | planned |
| H5 | Unpaired key attempts IK | Integration | Responder closes TCP; no session; no frame sent | 1 | planned |
| H6 | Every handshake failure path | Unit | No bytes written before close; error reported locally only | 1 | planned |
| H7 | Wrong prologue; `kind` changes mid-handshake; IK failure | Unit, integration | Handshake fails; no XX fallback | 1 | planned |
| H8 | Replay a captured handshake message | Integration | Handshake fails | 1 | planned |
| H9 | Open many TCP connections that never complete the handshake | Integration (fake clock) | Concurrent handshake cap enforced; all time out after 10 s; memory bounded | 1 | planned |
| H10 | Two peers connected at once | Integration | Frames from peer A's connection never decrypt under peer B's keys; identity always from the Noise static key | 1 | planned |
| H10 | — | Review | No code path derives identity from name or announcement | 1 | review |

### 4.3 Session and framing

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| S1 | Capture a session with `tcpdump`; search for known plaintext | System | Plaintext absent | 1 | planned |
| S2 | Flip each bit of header and payload of an encrypted frame | Unit | Every flip → `DECRYPT_FAILED`, plaintext never returned | 1 | planned |
| S3 | Duplicate, skipped and swapped `seq` | Unit | Fatal `REPLAY_DETECTED` | 1 | planned |
| S4 | Encrypt N frames, collect nonces per key | Unit | No (key, nonce) pair repeats; rekey changes the key; `seq = 2^64-1` refused | 1 | planned |
| S4 | — | Review | Nonce derivation has a single implementation | 1 | review |
| S5 | Replay a frame from connection A on connection B | Integration | Rejected (`conn_id` mismatch or decrypt failure) | 1 | planned |
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
| F5 | Out-of-range chunk index; too many concurrent transfers or in-flight chunks | Unit | Rejected; limits enforced | 2 | planned |
| F6 | Modify a partial file on disk, then resume | Integration | Modified chunks detected and re-fetched | 3 | planned |

### 4.5 Local storage

| ID | Test | Level | Pass criterion | Phase | Status |
|----|------|-------|----------------|-------|--------|
| L1 | — | Review | Private key only goes through the keystore API | 1 | review |
| L2 | Edit the trust store file | Unit | Integrity check fails; store refused | 1 | planned |
| L2 | File permissions after creation | Unit (Linux) | `0600` | 1 | planned |
| L3 | Modify, delete or reorder a message record | Unit | Hash chain verification fails | 7 | planned |
| L4 | — | Review | `sodium_memzero` on every key buffer at teardown | 1 | review |
| L5 | Run integration tests with debug logging; grep logs for key bytes, plaintext markers, SAS | Integration | No match | 1 | planned |
