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
