# 2Link

Two-PC secure messaging and file-transfer protocol: a custom application protocol,
a reusable C++20 networking core, and (later) a Qt 6 desktop app.

Status: **Phase 0 — foundation**. See [`task.md`](task.md) for the current task.

## Build

Requirements: CMake ≥ 3.24, a C++20 compiler (GCC 13+, Clang 16+, MSVC 19.36+), Git.
Dependencies are fetched by CMake (GoogleTest for now).

```bash
cmake --preset debug          # or: asan, release
cmake --build --preset debug -j
ctest --preset debug
./build/debug/apps/cli/2link
```

## Layout

```
apps/cli/        command-line front end (first implementation target)
src/core/        shared types, version, utilities
src/framing/     frame format, serialization, bounds-checked parser
tests/           GoogleTest unit tests (CTest)
docs/            protocol spec, threat model
```

Planned modules, added in their phase: `src/crypto` (libsodium + Noise),
`src/session`, `src/transport` (TCP, later UDP), `src/discovery`,
`src/transfer`, `src/storage` (SQLite), `apps/desktop` (Qt 6).
