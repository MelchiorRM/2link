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
