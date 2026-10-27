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

## Period history and reporting

State schema version 2 stores authoritative balances, raw baselines, sparse UTC
minute-delta buckets, coverage metadata, uncertainty intervals, and the last
same-boot monotonic observation in the same atomic JSON checkpoint. History is
not a separately committed database. Zero-traffic minutes need no bucket;
coverage advances through successful samples even when usage is zero.

Each port's `history` contains `since`, a nondecreasing `retained_since` floor,
`buckets` of `[minute_epoch, upload_bytes, download_bytes]`, and merged `gaps` of
`[start_epoch, end_epoch]`. Buckets are sorted and unique. All byte values are
nonnegative integers, and retained history cannot exceed the cumulative balance.
History retention is 31 days; pruning never changes the all-time counters.

The first successful version-1 sample migrates state to version 2. It charges the
latest raw delta to the cumulative balance, then starts empty history at that
observation. It never invents historical timestamps for legacy usage. Fresh
version-2 ports record their first sampled delta in history.

`Today` starts at calendar midnight in the selected IANA timezone (`UTC` by
default), including daylight-saving transitions. Rolling windows span 24 hours,
seven days, and 30 days, with starts rounded down to UTC minute boundaries.
Deltas are assigned to the minute when sampled, not divided among estimated
packet timestamps. Future-minute buckets are excluded from current windows.

Reports distinguish `complete` coverage, `partial` coverage that starts after the
window, and `incomplete` windows overlapping a sampling/recovery/clock gap.
Intervals longer than 120 seconds, counter resets, generation recovery, and boot
rebasing mark uncertainty. Wall-clock rollback or divergence from same-boot
monotonic elapsed time also marks uncertainty. Boot rebasing clears the previous
monotonic baseline. A clock-change observation does not prune retained history.

Incomplete values are neither guaranteed lower bounds nor exact period usage:
delayed observations can move earlier traffic into a later period. All-time uses
only authoritative balances and is marked incomplete when accounting events
exist. Original cumulative JSON keys remain available; `periods` and history,
timezone, and resolution metadata are additive.

Text output has five rows and download/upload/total columns. ANSI colors are
optional and supplement textual status. Auto color requires a TTY, no `NO_COLOR`
variable, and a non-`dumb` terminal. JSON never includes ANSI codes.

Continuous traffic can create about 44,640 minute buckets per port over 31 days.
The ten-second timer rewrites the atomic JSON checkpoint about 8,640 times daily.
For large deployments, measure storage and checkpoint latency; a future SQLite
migration must move all authoritative accounting together, not split transactions
between JSON balances and a second history store.

## Installation

The installer runs the unit/installer suite before installing files. A separate
installer lock serializes installations, and `mktemp` creates collision-free backup
directories even when two installations have the same timestamp. Existing CLI and
systemd files, the firewall snapshot, and an existing checkpoint are backed up.
The installer validates the new units, reloads systemd, and enables restoration
and the checkpoint timer. It does not choose a port, flush the firewall, or
restart a tunnel service.

Before replacing an existing executable, the installer uses it to sync and backs
up the checkpoint. The new writer migrates version-1 state on its first sample.
The old version-1 reader rejects version-2 state; it must not be reinstalled as a
live downgrade. Restoring an older state can discard balances or replay deltas.
Keep state/code backups together and design compatible rollback explicitly.

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
