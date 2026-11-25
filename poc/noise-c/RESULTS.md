# Noise library proof-of-concept: results

Task 0.7, run on 2026-11-26. It decides whether spec v0.1 §4–5 can be frozen
with this library.

**Verdict: noise-c + libsodium meets every requirement on Linux and Windows/MSVC,
with two accommodations: a 25-line `Rekey()` shim, and our own CMake build.**

## Setup

| Component | Version |
|-----------|---------|
| noise-c | `rweather/noise-c` @ `cfe2541` (2023-12-07), MIT |
| libsodium | official sources via `robinlinden/libsodium-cmake` @ `9b2848d` (submodule `93a7d0d`, close to 1.0.22), ISC |
| Backend | noise-c's libsodium backend for ChaCha20-Poly1305, Curve25519, BLAKE2b |
| Platforms | Ubuntu 24.04 GCC 13 with ASan + UBSan; Windows 2022 MSVC 19.x (CI) |

## Requirements

| Requirement (spec) | Result | Evidence (`noise_poc_test.cpp`) |
|--------------------|--------|---------------------------------|
| XX handshake (§4.4) | Pass | `Handshake.XXExposesHashAndRemoteStatic` |
| IK handshake with pinned key (§4.8) | Pass | `Handshake.IKWithPinnedKey` |
| `25519_ChaChaPoly_BLAKE2b` and interop with another implementation | Pass | `CacophonyVectors.XX_…`, `CacophonyVectors.IK_…`: every handshake and transport ciphertext matches the Cacophony reference vectors byte for byte |
| Handshake hash available (§4.5 SAS) | Pass | 64-byte hash, equal on both sides; two runs give different hashes |
| Remote static key available (§4.7 pinning) | Pass | Both sides read the other's authenticated key |
| IK fails on a changed responder key (§4.8) | Pass | `Handshake.IKWithWrongPinnedKeyFails` |
| Prologue binding (§4.2) | Pass | `Handshake.PrologueMismatchFails` |
| Tampered handshake rejected | Pass | `Handshake.TamperedMessageFails` |
| CipherState with implicit counter, no `SetNonce` (§5.2) | Pass | `Transport.CounterTracksSeqWithHeaderAsAd`: counter == `seq` for 1 000 frames on both sides, 28-byte header as AD |
| Replay, reorder, header tampering fail (§5.3) | Pass | `Transport.ReplayFails`, `ReorderFails`, `HeaderTamperFails` |
| Counter `2^64-1` refused (§5.3) | Pass | `Transport.ReservedMaxNonceRefused` |
| `Rekey()` keeping the counter (§5.4) | **Pass with shim** | `Rekey.MatchesSpecDefinitionAndKeepsCounter` checks the new key against an independent libsodium computation of the spec formula; `BothSidesStayInSync`, `OneSidedRekeyFails`, `OldKeyNoLongerDecrypts` |
| Builds on Linux and Windows/MSVC | **Pass with own CMake** | CI jobs `noise-poc (ubuntu-24.04)` and `noise-poc (windows-2022)`: 21/21 tests each |

## Findings

1. **No `Rekey()` in noise-c.** The shim (`noise_rekey.c`) implements
   `REKEY(k) = first 32 bytes of ENCRYPT(k, 2^64-1, "", zeros[32])` through
   noise-c's internal CipherState hooks, then restores the counter. It depends on
   the `NoiseCipherState` layout in `src/protocol/internal.h`. If that layout
   changes, `Rekey.MatchesSpecDefinitionAndKeepsCounter` fails, because it checks
   the result against libsodium directly.
2. **No CMake and no MSVC support upstream.** noise-c uses autotools and always
   builds Curve448/NewHope, whose Goldilocks code uses GCC-only `__attribute__`.
   Our CMake build compiles only what 2Link needs and stubs the two unused
   constructors. No noise-c source file is modified.
3. **Dangling out-pointer on error.** When a `*_new_*` call fails, noise-c frees the
   object but leaves the caller's pointer set. Our wrapper must discard the pointer
   on any error return (RAII handles this).
4. **Maintenance.** The last upstream commit was in December 2023. Treat it as
   frozen third-party code: pin the commit, review it ourselves, upstream the
   rekey shim if possible.
5. **Unused code is compiled.** The reference BLAKE2s and AES-GCM implementations are
   built because noise-c's name tables reference them. They are never selected by
   2Link's protocol names. Removing them would require modifying noise-c.
6. **Upstream warnings.** One MSVC warning (C4319) is in libsodium's `codecs.c`.
   noise-c and libsodium are compiled without our `-Werror` / `/WX`.

## Alternatives considered

| Option | Why not chosen |
|--------|----------------|
| Noise\* (Inria, formally verified C) | One generated library per pattern and suite; brings its own peer list and state machine, which would duplicate ours; needs the HACL\* build; no documented rekey; last push June 2024 |
| NoisePQC++ | Post-quantum research code, 2 stars, not vetted |
| Own Noise implementation on libsodium | Against the "vetted library" requirement |

## Recommendation

Adopt noise-c @ `cfe2541` with the libsodium backend, the rekey shim and our CMake
build. For Phase 1:

- vendor the needed noise-c sources under `third_party/noise-c/` (pinned, license
  kept), or keep FetchContent at the pinned commit;
- keep the PoC tests as the integration's conformance tests (vectors + rekey);
- wrap noise-c in a small C++ RAII layer that never exposes raw pointers after
  errors.

Spec change needed to freeze v0.1 (§5.1): the library alone does not provide
`Rekey`, so the requirement becomes "the Noise implementation (the library plus
2Link's shim) MUST provide `EncryptWithAd`, `DecryptWithAd` and `Rekey`". §4 and
the rest of §5 need no change.
