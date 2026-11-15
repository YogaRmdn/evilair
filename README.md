# EvilAir

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/YogaRmdn/evilair)
[![Python](https://img.shields.io/badge/python-3.10%2B-green)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://www.kernel.org/)

EvilAir is a professional command-line tool to **discover, monitor, and shape the bandwidth** of devices on your local area network. It combines ARP discovery, live traffic accounting, and Linux traffic control (HTB + iptables) into one interactive shell.

> Author: [YogaRmdn](https://github.com/YogaRmdn) — `github.com/YogaRmdn`

## Features

- **Host discovery** — fast batched ARP sweep plus a root-free fallback via the kernel ARP cache and ping sweep.
- **Bandwidth shaping** — per-host upload/download limits and full blocking, powered by HTB qdisc and iptables marks.
- **Live monitoring** — real-time per-host upload/download rates and totals.
- **MITM positioning** — bidirectional ARP spoofing with automatic restoration on exit.
- **Reconnection watcher** — migrates limits when a device changes IP (same MAC).
- **Interactive shell** — tab completion, persistent history, arrow-key command menu (`menu`).
- **Dry-run mode** — preview every system command without touching the network.
- **Export** — save the host list as JSON or CSV.

## Requirements

- Linux (kernel HTB qdisc + iptables)
- Python 3.10+
- System tools: `tc`, `iptables`, `sysctl`, `ip`, `ping`
- Root privileges for live use (shaping traffic and crafting ARP packets)
- Any 802.11 band works (2.4 GHz and 5 GHz alike) as long as the access point
  does not isolate clients from each other

## Installation

```bash
git clone https://github.com/YogaRmdn/evilair.git
cd evilair
python -m venv ~/Python-env
~/Python-env/bin/pip install -e .
```

## Usage

```bash
# Interactive shell (requires root)
sudo ~/Python-env/bin/evilair

# Preview without touching the system
~/Python-env/bin/evilair --dry-run -c "import; hosts"

# Run a few commands and exit
sudo ~/Python-env/bin/evilair -c "scan; limit 0 512kbit; monitor"
```

Or, from the project folder:

```bash
./run.py --dry-run -c "import; hosts"
sudo ./run.py
```

### CLI options

| Option | Description |
|---|---|
| `-i, --interface` | Network interface (auto-detected) |
| `-g, --gateway-ip` | Gateway IPv4 address |
| `-m, --gateway-mac` | Gateway MAC address |
| `-n, --netmask` | Netmask or CIDR length |
| `-c, --exec` | Run `;` separated commands and exit |
| `-f, --flush` | Remove leftover EvilAir rules at start |
| `--dry-run` | Print commands instead of applying them |
| `--colorless` | Disable colors |
| `--debug` | Verbose logging |
| `--list-interfaces` | Show interfaces and exit |
| `-V, --version` | Show version |

## Shell commands

| Command | Description | Example |
|---|---|---|
| `scan [target]` | ARP sweep the LAN | `scan 192.168.1.0/24` |
| `import [--probe]` | Import hosts from the kernel ARP cache | `import --probe` |
| `hosts` / `ls` | List discovered hosts | `hosts` |
| `add <ip> [--mac] [--name]` | Add a host manually | `add 192.168.1.10 --name laptop` |
| `limit <target> <rate>` | Cap bandwidth | `limit 0 512kbit` |
| `block <target>` | Cut internet access | `block 4` |
| `block-all [--scan]` | Block every discovered host (gateway skipped) | `block-all --scan` |
| `free <target>` | Remove limits/blocks | `free all` |
| `free-all` | Remove limits/blocks from every host | `free-all` |
| `monitor [--interval ms]` | Live bandwidth view | `monitor --interval 500` |
| `analyze [target] [--duration s]` | Measure top consumers | `analyze all --duration 10` |
| `watch add\|remove\|...` | Detect reconnections | `watch add 0` |
| `export <path> [--csv]` | Save host list | `export hosts.json` |
| `flush` | Delete all EvilAir rules/qdisc | `flush` |
| `menu` / `m` | Interactive arrow-key menu | `menu` |
| `update` / `upd` | Pull latest version from GitHub and reinstall | `update` |
| `help`, `clear`, `quit` | Utilities | `help` |

Targets accept host ids (`0`), ranges (`1-3`), comma lists, IPs, MACs, or `all`.
Bulk targets (`all`, `block-all`, `limit all`) automatically skip the gateway and
this machine's own address; target them explicitly by IP if you really mean it.

## Example session

```
evilair (0 hosts) › scan
evilair (14 hosts) › limit 0 512kbit
evilair (14 hosts, 1 managed) › block 4
evilair (14 hosts, 2 managed) › monitor
evilair (14 hosts, 2 managed) › free all
evilair (14 hosts) › export hosts.json
```

## Safety

- Only use EvilAir on networks you own or are authorized to test.
- Use `--dry-run` first to preview actions.
- EvilAir restores network settings automatically on exit (atexit + signal handlers).
- ARP spoofing and traffic shaping require root and can disrupt connectivity if misused.

## Development

```bash
~/Python-env/bin/python -m unittest discover -s tests
```

All tests should pass.

The interpreter used by `run.py` and the `update` command is auto-detected
(project `.venv`, then `~/Python-env`). Override it with `EVILAIR_PYTHON=/path/to/python`.

## License

MIT — based on [bitbrute/evillimiter](https://github.com/bitbrute/evillimiter).

## Author

[YogaRmdn](https://github.com/YogaRmdn) — `github.com/YogaRmdn`
EOF