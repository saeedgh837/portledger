# PortLedger accounting design

## Boundary

The unit of accounting is a local listening port on a single selected interface.
An nftables `inet port_traffic` table contains input/output base chains at priority
`-150`, named per-port counters, and interface/protocol/port matches. Incoming
rules match destination ports; outgoing rules match source ports. TCP and UDP
traffic from both IP versions contributes to the same account.

The meter adds no packet verdict rules and does not replace other firewall tables.
It does not count the forwarding path or separately meter a tunnel's transport.
These counters describe matching IP-stack traffic, not authenticated customers,
application payload, or provider billing. Customer attribution requires a dedicated
port. Port reassignment does not create a new accounting period.

## Durable balances

Each port stores cumulative integer `rx_bytes`/`tx_bytes` and the last sampled raw
kernel values. For an ordinary sample, add `current - previous` to the cumulative
balance and replace the raw baseline. Repeating the same sample adds zero. Decimal
GB is derived only for presentation; byte accounting stays integer-exact.

Every CLI operation that accesses accounting uses the same exclusive Linux
`flock`. State is written to a private temporary file, flushed and fsynced, replaced
atomically, and followed by parent-directory fsync. A failed or corrupt state read
must not silently become an empty account.

The state directory is `/var/lib/port-traffic` by default, mode `0700`. State and
lock files are `0600`. Reports checkpoint live readings. A systemd timer requests a
checkpoint every ten seconds; boot restoration and graceful shutdown use the same
serialized accounting path.

## Table generations and recovery

The table comment carries a random generation identifier that must match the
saved account. Raw values are meaningful only within that generation.

- **Missing table:** retain cumulative totals, persist a new generation and zero
  raw baselines before creating kernel objects, then record a completeness warning.
- **Unknown generation:** refuse ambiguous accounting rather than overwriting a
  foreign or stale table.
- **Missing counter or changed rule:** reject incomplete or mismatched accounting.
  Validation checks hooks, priority, policy, interface, protocols, ports, counter
  references, comments, and expected rule count.
- **Decreased raw counter:** retain totals, add the new raw value, and record a
  reset warning. Uncheckpointed traffic before an external reset may be missing.
- **Boot change with existing matching counters:** validate the rules, retain
  cumulative balances, and adopt current counters as new raw baselines without
  charging them again. Save boot ID, baselines, totals, and `boot_rebase` warning
  atomically. Traffic before the new baseline cannot be recovered reliably.

Adding a port first persists `pending` intent, then installs its counters and rules
in an nft transaction. Recovery distinguishes absent, fully installed, and partially
installed counter pairs. This makes an interrupted add recoverable without
zeroing existing cumulative balances.

## Installation

The installer runs the unit/installer suite before installing files. A separate
installer lock serializes installations, and `mktemp` creates collision-free backup
directories even when two installations have the same timestamp. Existing CLI and
systemd files, the firewall snapshot, and an existing checkpoint are backed up.
The installer validates the new units, reloads systemd, and enables restoration
and the checkpoint timer. It does not choose a port, flush the firewall, or
restart a tunnel service.

## Limits

Root firewall changes are outside the meter's transaction boundary. In particular,
replaying old counters with the same generation during the same boot can look like
new traffic. Such replay is unsupported; do not restore old live counters.

The checkpoint interval is nominal. Scheduling, storage, shutdown, and restoration
delays can make a loss window longer than ten seconds. Kernel table recovery and
boot rebasing preserve known balances but do not guarantee gap-free totals.
Warnings must be considered before relying on measurements for billing.

State directories do not namespace kernel tables. Tests using alternate state must
also use an isolated network namespace, not another directory against the live table.

## Verification

The unit/installer suite has 17 tests. The isolated Linux integration suite has 16,
including exact UDP counts, TCP traffic, concurrent writers, installation
interruptions, lost tables, replayed counters, and modified rules. Its entry point
refuses the host network namespace. Boot-ID simulations exercise recovery logic;
they are not a claim that an actual production reboot was performed.
