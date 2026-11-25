# Current task — Phase 0: Foundation

Spec v0.1, threat model, repository, CMake and test setup, frame serialization and parsing.

Status legend: `done` · `in progress` · `pending` · `blocked`

## Main tasks

| # | Task | Status |
|---|------|--------|
| 0.1 | Repository and environment setup | done |
| 0.2 | Build system and test harness | done |
| 0.3 | Protocol specification v0.1 | pending |
| 0.4 | Threat model document | pending |
| 0.5 | Frame serialization and parsing | pending |
| 0.6 | Testing strategy document | pending |

## Subtasks

### 0.1 Repository and environment setup — `done`
- [x] Local git repo (`main` branch), design doc kept local-only (`.git/info/exclude`)
- [x] Private GitHub repo created and linked as `origin`
- [x] `.gitignore`, `.editorconfig`, `.clang-format`
- [x] README with build instructions and module layout
- [x] Toolchain verified: GCC 13.3, CMake 3.28, git, gh (WSL Ubuntu 24.04)

### 0.2 Build system and test harness — `done`
- [x] Top-level CMake project, C++20, strict warnings (`cmake/CompilerOptions.cmake`)
- [x] Presets: `debug`, `release`, `asan` (ASan + UBSan), `ci` (sanitizers + `-Werror`)
- [x] GoogleTest via FetchContent, CTest discovery
- [x] Module skeleton: `src/core`, `src/framing`, `apps/cli`, `tests/`
- [x] Smoke tests pass under ASan/UBSan
- [x] GitHub Actions CI workflow (configure, build, test)
- [ ] Windows/MSVC build check — pending (do before Phase 1)

### 0.3 Protocol specification v0.1 — `pending`
- [ ] Frame header layout: field widths, byte order, version field
- [ ] Message type registry (control, messaging, transfer)
- [ ] Max frame size and per-field limits
- [ ] Which header fields are AEAD associated data
- [ ] Handshake lifecycle (Noise XX pairing, Noise IK reconnect)
- [ ] Session state machine and transitions
- [ ] Short authentication string: derivation, encoding, truncation
- [ ] Error / close codes

### 0.4 Threat model document — `pending`
- [ ] Assets, threat actors, trust boundaries
- [ ] Attacks and mitigations per layer (discovery, handshake, session, framing, transfer)
- [ ] Explicit out-of-scope list for V1

### 0.5 Frame serialization and parsing — `pending`
- [ ] Endian-explicit integer read/write helpers (bounds-checked)
- [ ] Frame header struct + encoder
- [ ] Incremental parser: partial reads, multiple frames per read, frames spanning reads
- [ ] Reject: bad version, oversize length, unknown type, truncated input
- [ ] No allocation sized from unvalidated remote input
- [ ] Unit tests for every rejection path and the split-read cases
- [ ] Fuzz target for the parser (libFuzzer)

### 0.6 Testing strategy document — `pending`
- [ ] Security, reliability, throughput and latency test definitions
- [ ] Measurement method and pass criteria for each
- [ ] Tooling: sanitizers, fuzzing, `tc netem`, `iperf3` baseline
