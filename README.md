# 2Link

Two-PC secure messaging and file-transfer protocol: a custom application protocol,
a reusable C++20 networking core, and (later) a Qt 6 desktop app.

Status: **Phase 1 complete** — discovery, TCP, Noise handshake, pairing and encrypted
chat between two PCs (spec v0.1.4). Next: Phase 2, file transfer.

## Build

Requirements: CMake ≥ 3.25, a C++20 compiler (GCC 13+, Clang 16+, MSVC 19.36+), Git,
and [vcpkg](https://github.com/microsoft/vcpkg). Library dependencies (libsodium,
standalone Asio, GoogleTest) are declared in `vcpkg.json` and installed by vcpkg
during the first configure; noise-c is fetched at a pinned commit by CMake.

On Debian/Ubuntu, install the system packages listed in
[`requirements.txt`](requirements.txt):

```bash
sed 's/#.*//' requirements.txt | xargs sudo apt-get install -y
```

One-time vcpkg setup:

```bash
git clone https://github.com/microsoft/vcpkg ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh -disableMetrics      # Windows: bootstrap-vcpkg.bat
export VCPKG_ROOT=~/vcpkg                        # add to your shell profile
```

The presets read `VCPKG_ROOT`. Package versions are pinned by `builtin-baseline` in
`vcpkg.json`, not by your vcpkg checkout.

```bash
cmake --preset debug          # or: asan, release
cmake --build --preset debug -j
ctest --preset debug
./build/debug/apps/cli/2link
```

Fuzzing (requires Clang with libFuzzer):

```bash
cmake --preset fuzz && cmake --build --preset fuzz --target fuzz_frame_parser
./build/fuzz/tests/fuzz/fuzz_frame_parser -max_total_time=60 tests/fuzz/corpus
```

With GCC, the same binary replays input files: `fuzz_frame_parser <files...>`.

## Using the CLI

On each PC, once:

```bash
2link id                      # creates this device's key; prints its device ID
```

Pair two PCs (both users must compare the 6-digit code and type `y`):

```bash
2link pair --listen           # PC A: opens a 5-minute pairing window
2link pair 192.168.1.20       # PC B: A's address
```

Then chat. Each side finds the other on the LAN, or use `--host`:

```bash
2link chat <name-or-id>       # on both PCs; /quit to leave
2link chat laptop --host 192.168.1.20
2link peers [--scan]          # paired devices; --scan lists devices on the LAN
```

TCP port 47821 and UDP port 47820 must be reachable on the LAN. To try it on
one machine, give each instance its own `--data-dir` and `--port`.

## Layout

```
apps/cli/        command-line front end (first implementation target)
src/core/        shared types, version, utilities
src/framing/     frame format, serialization, bounds-checked parser
src/crypto/      libsodium + noise-c wrapper (keys, handshakes, CipherState)
src/identity/    device identity, device_id, keystore, trust store
src/session/     encrypted frames, seq/replay checks, rekeying
src/handshake/   HANDSHAKE frames, XX/IK driver, TLV payloads, SAS
src/connection/  connection state machine, pairing window and rate limiter
src/transport/   TCP on standalone Asio: links, node, primary/bulk rules
src/discovery/   UDP announcements, bounded device table
third_party/     pinned noise-c build and 2Link's shim
tests/           GoogleTest unit tests (CTest), tests/fuzz fuzz targets
docs/            protocol-spec.md, threat-model.md, testing-strategy.md
```

Planned modules, added in their phase: `src/transfer`, `src/storage` (SQLite),
`apps/desktop` (Qt 6).
