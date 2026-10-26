# PortLedger

Per-port traffic accounting for Ubuntu servers. Track cumulative upload, download,
and their total in decimal gigabytes without restarting a tunnel service or
replacing the existing firewall.

[راهنمای فارسی](README-fa.md) · [Accounting design](docs/architecture.md)

PortLedger is the project name. The installed command remains **`port-traffic`**.

## What it measures

- TCP and UDP, combining IPv4 and IPv6 in each port's account.
- Incoming destination-port traffic as **upload** (client to server).
- Outgoing source-port traffic as **download** (server to client).
- Integer byte totals, plus decimal GB with six decimal places.
- Local input/output traffic on one selected interface, using nftables named counters.

**Scope:** use this for a local listening port, including a customer-facing tunnel
listener. It does not meter DNAT/forwarded traffic or identify individual users
sharing a port. Assign a dedicated port to each customer if you need customer-level
attribution.

## Requirements

- Ubuntu with systemd and a kernel supporting nftables.
- Python 3.10 or newer. The meter uses only the Python standard library.
- `nftables`, `iproute2`, and the usual systemd/coreutils/util-linux tools, including
  `flock` and `mktemp`.
- Root privileges for installation, kernel counters, and protected accounting state.

Install missing packages on Ubuntu:

```bash
sudo apt-get update
```

```bash
sudo apt-get install python3 nftables iproute2 util-linux
```

## Install

Clone the repository with an account that has access:

```bash
git clone https://github.com/saeedgh837/portledger.git
```

```bash
cd portledger
```

Inspect the installer, then run it from the checkout:

```bash
sudo sh install.sh
```

The installer runs the unit/installer tests, takes a private firewall snapshot,
backs up existing installed files, installs the CLI and systemd units, and enables
boot restoration and periodic checkpoints. It does not flush the ruleset or restart
tunnel services. Existing saved accounts are retained on reinstall.

The installer does **not** register a port automatically.

## Quick start

Replace `8443` and `eth0` with the listening port and public interface you intend
to meter:

```bash
sudo port-traffic add 8443 --interface eth0
```

```bash
sudo port-traffic 8443
```

The report contains `Upload`, `Download`, `TOTAL`, `Exact total bytes`, and
`Since (UTC)`. One GB is exactly **1,000,000,000 bytes**, not one GiB.

If `--interface` is omitted, the meter selects the unique interface from the
IPv4 default routes. Ambiguous default interfaces require an explicit choice.
All registered ports share that interface; changing it on an active account is
rejected to avoid changing the accounting basis.

Reading a report or adding an already registered port does not reset its totals.
Port reassignment does not start a new billing period. There is no reset/remove
command in this version.

## Commands

Show one port as JSON:

```bash
sudo port-traffic show 8443 --json
```

List all registered ports:

```bash
sudo port-traffic list
```

```bash
sudo port-traffic list --json
```

Check rules, state, and accounting warnings:

```bash
sudo port-traffic doctor
```

`doctor` returns 0 for healthy initialized accounting without warnings, 2 when
accounting is valid but has completeness warnings, and a nonzero error for invalid
or uninitialized state. Review warnings before using totals for billing.

Write a current checkpoint:

```bash
sudo port-traffic sync
```

Check the automatic checkpoint timer:

```bash
systemctl status port-traffic-sync.timer
```

`restore` is used by the boot service. `--state-dir PATH` selects an alternate state
directory for isolated testing; it does not create an independent nftables table.
Do not run multiple state directories against the same network namespace.

## Persistence and operational limits

- State is stored in `/var/lib/port-traffic/state.json`. The directory is mode
  `0700`; state and lock files are mode `0600`.
- Writers use a process lock and atomic, fsynced state replacement. Reports also
  checkpoint the live counters. A systemd timer normally checkpoints every ten seconds.
- Boot restoration retains saved cumulative balances. Graceful shutdown requests
  a final checkpoint.
- A power failure, disk error, forced termination, or external firewall change can
  lose traffic after the last successful checkpoint. Ten seconds is a nominal
  interval, **not a guaranteed maximum loss window**.
- Missing managed tables are rebuilt while retaining saved totals, with a warning.
  Unknown table generations, altered rules, missing counters, and corrupt state
  produce errors rather than silently inventing balances.
- If a boot change is detected with existing managed counters, a conservative
  baseline prevents replaying those counters. The `boot_rebase` warning means
  traffic before that new baseline may be missing.
- **Do not replay old `port_traffic` counters during the same boot.** A same-generation
  counter replay cannot always be distinguished from new traffic. Do not delete or
  hand-edit live state, and do not flush the ruleset while accounting is active.
- These are IP-stack bytes, including headers and retransmissions, not application
  payload or guaranteed hosting-provider billing figures. Traffic before activation
  is not reconstructed from historical counters.

Before backing up state, request a checkpoint:

```bash
sudo port-traffic sync
```

```bash
sudo cp -p /var/lib/port-traffic/state.json /root/port-traffic-state-backup.json
```

Installer snapshots are stored under `/var/lib/port-traffic/backups/` in separate,
collision-free directories. They contain potentially sensitive firewall details;
keep them private. A snapshot is not a safe instruction to replay live counters.

## Tests

Unit and installer tests:

```bash
python3 -m unittest discover -s tests -v
```

There are 17 tests in this suite. The two POSIX installer tests skip on Windows.

Real nftables/kernel integration tests, in a fresh network namespace:

```bash
sudo unshare --net -- python3 tests/integration_linux.py
```

The 16 integration tests cover exact IPv4/IPv6 UDP byte counts, TCP overhead,
unrelated ports and firewall tables, interface selection, concurrent checkpoints,
table loss, interrupted port installation, cross-boot counter replay, and rule
tampering. The runner refuses the host network namespace. Simulated boot recovery
tests do not prove an actual production reboot.

## Repository contents

The repository contains the portable meter, installer, systemd units, tests, and
English/Persian documentation. Host-specific SSH helpers, deployment logs, runtime
state, backups, and generated archives are intentionally excluded.
