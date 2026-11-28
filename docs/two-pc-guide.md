# Running 2Link on two PCs

A step-by-step guide to pairing two real PCs on the same network (same Wi-Fi or
switch) and chatting between them with the `2link` CLI (Phase 1, spec v0.1.4).

## 1. Build `2link` on each PC

### Linux (native, not WSL)

```bash
sudo apt-get install -y $(sed 's/#.*//' requirements.txt)
git clone https://github.com/microsoft/vcpkg ~/vcpkg && ~/vcpkg/bootstrap-vcpkg.sh -disableMetrics
export VCPKG_ROOT=~/vcpkg                  # add to ~/.bashrc
git clone git@github.com:MelchiorRM/2link.git && cd 2link
cmake --preset release && cmake --build --preset release -j
./build/release/apps/cli/2link version
```

Run the `apt-get` line from inside the cloned repository, or install the packages
listed in [`requirements.txt`](../requirements.txt) by hand first.

### Windows (native)

Needs Visual Studio 2022 with the "Desktop development with C++" workload, and
Git. In a **Developer PowerShell for VS 2022**:

```powershell
git clone https://github.com/microsoft/vcpkg $HOME\vcpkg; & $HOME\vcpkg\bootstrap-vcpkg.bat -disableMetrics
$env:VCPKG_ROOT = "$HOME\vcpkg"
git clone git@github.com:MelchiorRM/2link.git; cd 2link
cmake --preset msvc
cmake --build --preset msvc --config Release
.\build\msvc\apps\cli\Release\2link.exe version
```

### WSL

By default WSL sits behind NAT, so the other PC cannot reach it. Either build
natively on Windows (recommended), or, on Windows 11, enable mirrored networking
in `%USERPROFILE%\.wslconfig` and run `wsl --shutdown`:

```ini
[wsl2]
networkingMode=mirrored
```

Discovery broadcasts may still not reach WSL; connect with `--host` (step 5).

## 2. Open the firewall on both PCs

2Link uses **TCP 47821** (connections) and **UDP 47820** (discovery).

- **Windows:** the first time `2link` listens, Windows asks whether to allow it.
  Allow it on **Private** networks, and make sure your network profile is
  Private, not Public.
- **Linux (ufw):**

  ```bash
  sudo ufw allow 47821/tcp && sudo ufw allow 47820/udp
  ```

## 3. Create an identity on each PC and find its address

```bash
2link id                 # prints the device name and ID; add --name "office-pc" to choose a name
ip -4 addr               # Linux: e.g. 192.168.1.20
ipconfig                 # Windows: "IPv4 Address"
```

## 4. Pair (once)

On **PC A**:

```bash
2link pair --listen
```

On **PC B**, with A's address:

```bash
2link pair 192.168.1.20
```

Both screens show a code such as `551 146`. **Check that both screens show the
same code**, then type `y` on each. Both print `Paired with "...".` A different
code on the two screens means someone is in the middle: answer `n`.

Check the result:

```bash
2link peers              # each PC lists the other
2link peers --scan       # also lists devices seen on the LAN, marked [paired]
```

## 5. Chat

On both PCs, name the other device (its name or the start of its device ID):

```bash
2link chat office-pc     # on B
2link chat laptop        # on A
```

Each side finds the other through discovery, and you should see
`Connected to "..."` within about 5 seconds. Type messages and press Enter;
`/quit` leaves.

If discovery does not connect (WSL, or a router that blocks broadcast), point
one side at the other directly:

```bash
2link chat laptop --host 192.168.1.20
```

## 6. Things worth trying

- **Reconnection:** quit and run `chat` again; it reconnects without a code.
  Unplug the network cable or turn off Wi-Fi: after about 45 seconds it reports
  the disconnect, and it reconnects when the network returns.
- **Rejecting a pairing:** answer `n` on one side. Both sides abort and nothing
  is stored.
- **Identity-change warning:** on the second PC, create a fresh identity with
  the old name and pair again:

  ```bash
  2link pair --listen                                  # PC A
  2link pair 192.168.1.20 --data-dir /tmp/fake --name <B's old name>   # PC B
  ```

  PC A warns that it already trusts a different device with that name before
  you confirm.
- **Pairing window:** `pair --listen` closes after 5 minutes or after one
  successful pairing; pairing attempts at other times are refused.

## 7. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `Pairing failed: connection lost` or `timed out` right away | Firewall, wrong IP, or `pair --listen` is not running on the other PC |
| `pair` works but `chat` never says Connected | Discovery broadcast is blocked; use `--host` |
| `cannot listen on TCP port 47821` | Another `2link` is already running; add `--port 47900` here and `--host <ip>:47900` on the other PC |
| Mangled characters on Windows | Use Windows Terminal; 2link switches the console to UTF-8 |

## Where the data lives

| OS | Directory |
|----|-----------|
| Linux | `~/.local/share/2link` (or `$XDG_DATA_HOME/2link`) |
| Windows | `%LOCALAPPDATA%\2link` |

It holds the device key (`keys/`) and the trust store (`trust-store.bin`). Use
`--data-dir` to keep a separate identity, for example to run two instances on
one PC (each also needs its own `--port`). Deleting the directory gives the PC
a new identity, and every peer must pair with it again.
