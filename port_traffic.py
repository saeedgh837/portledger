#!/usr/bin/python3
"""Persistent, non-filtering per-port nftables accounting for local listeners."""
from __future__ import annotations

import argparse
from bisect import bisect_left
import copy
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

TABLE = "port_traffic"
PREFIX = "port-traffic:v1:"
DEFAULT_DIR = "/var/lib/port-traffic"
BUCKET_SECONDS = 60
RETENTION_SECONDS = 31 * 86400
MAX_SAMPLE_GAP = 120
CLOCK_TOLERANCE = 5


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Invalid timezone-aware timestamp") from exc


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def report_timezone(name):
    if name == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
        raise ValueError(f"Unknown timezone {name!r}; use an IANA name and install tzdata if needed") from exc


def history_start(now):
    epoch = int(timestamp(now).timestamp())
    return {"since": now, "retained_since": epoch, "buckets": [], "gaps": []}


def add_gap(history, start, end):
    start, end = sorted((start, end))
    intervals = sorted(history["gaps"] + [[start, end]])
    merged = []
    for left, right in intervals:
        if merged and left <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], right)
        else:
            merged.append([left, right])
    history["gaps"] = merged


def recovery_gap(state, now):
    if state["version"] == 2:
        end = int(timestamp(now).timestamp())
        start = int(timestamp(state["last_sync"] or now).timestamp())
        for entry in state["ports"].values():
            add_gap(entry["history"], start, end)


def valid_port(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,5}", value):
        raise ValueError("Port must be an ASCII number between 1 and 65535")
    if not 1 <= int(value) <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    return str(int(value))


def valid_interface(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", value):
        raise ValueError("Invalid interface name")
    return value


def byte_count(value):
    if type(value) is not int or value < 0:
        raise ValueError("Counter bytes must be nonnegative integers")
    return value


def record_event(state, kind, detail, now):
    state["events"].append({"time": now, "kind": kind, "detail": detail})
    state["events"] = state["events"][-100:]


def apply_sample(state, snapshot, now, monotonic_ns=None):
    if snapshot["generation"] != state["generation"]:
        raise ValueError("Kernel table generation does not match saved state; refusing ambiguous accounting")
    epoch = int(timestamp(now).timestamp())
    previous_epoch = int(timestamp(state["last_sync"]).timestamp()) if state["last_sync"] is not None else epoch
    elapsed = epoch - previous_epoch
    previous_mono = state.get("last_monotonic_ns")
    clock_change = elapsed < 0
    if monotonic_ns is not None:
        byte_count(monotonic_ns)
        if previous_mono is not None:
            real_elapsed = (monotonic_ns - previous_mono) / 1_000_000_000
            clock_change |= real_elapsed < 0 or abs(elapsed - real_elapsed) > CLOCK_TOLERANCE
    result = copy.deepcopy(state)
    migrating = result["version"] == 1
    result["version"] = 2
    result.setdefault("history_pruning_suspended", False)
    if clock_change:
        result["history_pruning_suspended"] = True
        record_event(result, "clock_change", "wall clock changed; period attribution is uncertain", now)
    for port, entry in result["ports"].items():
        if migrating:
            entry["history"] = history_start(now)
        history = entry["history"]
        sample_start = previous_epoch if state["last_sync"] is not None else int(timestamp(history["since"]).timestamp())
        if not migrating and (clock_change or epoch - sample_start < 0 or epoch - sample_start > MAX_SAMPLE_GAP):
            add_gap(history, sample_start, epoch)
        deltas = []
        for direction in ("rx", "tx"):
            name = f"p{port}_{direction}"
            if name not in snapshot["counters"]:
                raise ValueError(f"Missing kernel counter {name}; not reporting an incomplete balance")
            current = byte_count(snapshot["counters"][name])
            previous = byte_count(entry[f"raw_{direction}"])
            if current < previous:
                record_event(result, "counter_reset", f"{name}: possible unsaved bytes before external reset", now)
                add_gap(history, previous_epoch, epoch)
                delta = current
            else:
                delta = current - previous
            entry[f"{direction}_bytes"] += delta
            entry[f"raw_{direction}"] = current
            deltas.append(delta)
        # Legacy deltas have no reliable time attribution; they belong only in the all-time balance.
        if not migrating and any(deltas):
            minute = epoch // BUCKET_SECONDS * BUCKET_SECONDS
            buckets = history["buckets"]
            index = bisect_left(buckets, [minute])
            if index < len(buckets) and buckets[index][0] == minute:
                buckets[index][1] += deltas[0]
                buckets[index][2] += deltas[1]
            else:
                buckets.insert(index, [minute, *deltas])
        if not result["history_pruning_suspended"]:
            floor = max(history["retained_since"],
                        (epoch - RETENTION_SECONDS) // BUCKET_SECONDS * BUCKET_SECONDS)
            history["retained_since"] = floor
            history["buckets"] = [b for b in history["buckets"] if b[0] + BUCKET_SECONDS > floor]
            history["gaps"] = [[max(start, floor), end] for start, end in history["gaps"] if end >= floor]
    result["last_sync"] = now
    result["last_monotonic_ns"] = monotonic_ns
    return result


def new_generation(state, generation, boot_id, reason):
    result = copy.deepcopy(state)
    if result["generation"] is not None:
        now = utcnow()
        record_event(result, "restored", reason + "; totals retained; traffic after last checkpoint may be missing", now)
        recovery_gap(result, now)
    result["generation"] = generation
    if result["boot_id"] != boot_id:
        result["last_monotonic_ns"] = None
    result["boot_id"] = boot_id
    for entry in result["ports"].values():
        entry["raw_rx"] = 0
        entry["raw_tx"] = 0
    return result


def parse_snapshot(data):
    generation = None
    counters = {}
    rules = []
    chains = {}
    for obj in data["nftables"]:
        table = obj.get("table", {})
        if table.get("family") == "inet" and table.get("name") == TABLE:
            comment = table.get("comment", "")
            if not comment.startswith(PREFIX) or not re.fullmatch(r"[a-zA-Z0-9]+", comment[len(PREFIX):]):
                raise ValueError("An unowned port_traffic table already exists; will not modify it")
            generation = comment[len(PREFIX):]
        counter = obj.get("counter", {})
        if counter.get("family") == "inet" and counter.get("table") == TABLE:
            counters[counter["name"]] = byte_count(counter["bytes"])
        rule = obj.get("rule", {})
        if rule.get("family") == "inet" and rule.get("table") == TABLE:
            rules.append(rule)
        chain = obj.get("chain", {})
        if chain.get("family") == "inet" and chain.get("table") == TABLE:
            chains[chain["name"]] = chain
    if generation is None:
        raise ValueError("Managed kernel table is missing")
    return {"generation": generation, "counters": counters, "rules": rules, "chains": chains}


def validate_history(history, entry):
    timestamp(history["since"])
    byte_count(history["retained_since"])
    if not isinstance(history["buckets"], list) or not isinstance(history["gaps"], list):
        raise ValueError("Invalid history arrays")
    previous = -1
    totals = [0, 0]
    for bucket in history["buckets"]:
        if not isinstance(bucket, list) or len(bucket) != 3:
            raise ValueError("Invalid history bucket")
        minute, rx, tx = (byte_count(value) for value in bucket)
        if minute % BUCKET_SECONDS or minute <= previous or not (rx or tx):
            raise ValueError("Invalid or unsorted history bucket")
        previous = minute
        totals[0] += rx
        totals[1] += tx
    if totals[0] > entry["rx_bytes"] or totals[1] > entry["tx_bytes"]:
        raise ValueError("History exceeds the authoritative balance")
    previous = -2
    for gap in history["gaps"]:
        if not isinstance(gap, list) or len(gap) != 2:
            raise ValueError("Invalid history gap")
        start, end = (byte_count(value) for value in gap)
        if start > end or start <= previous + 1:
            raise ValueError("Invalid or overlapping history gap")
        previous = end


def validate_state(state):
    if type(state.get("version")) is not int or state["version"] not in (1, 2) or not isinstance(state.get("ports"), dict):
        raise ValueError("Unsupported or corrupt state; restore a checked backup, never delete the balance")
    valid_interface(state["interface"])
    if state["generation"] is not None and not re.fullmatch(r"[a-zA-Z0-9]+", state["generation"]):
        raise ValueError("Invalid saved generation")
    if not isinstance(state["events"], list):
        raise ValueError("Invalid saved events")
    if state["last_sync"] is not None:
        timestamp(state["last_sync"])
    if state["version"] == 2 and state["last_monotonic_ns"] is not None:
        byte_count(state["last_monotonic_ns"])
    if type(state.get("history_pruning_suspended", False)) is not bool:
        raise ValueError("Invalid history pruning guard")
    for port, entry in state["ports"].items():
        if valid_port(port) != port:
            raise ValueError("Noncanonical saved port")
        for key in ("rx_bytes", "tx_bytes", "raw_rx", "raw_tx"):
            byte_count(entry[key])
        timestamp(entry["since"])
        if state["version"] == 2:
            validate_history(entry["history"], entry)
    return state


def read_state(path):
    try:
        return validate_state(json.loads(Path(path).read_text(encoding="utf-8")))
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"Corrupt state {path}; refusing to zero existing totals") from exc


def save_state(path, state):
    path = Path(path)
    validate_state(state)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         suffix=".tmp", delete=False) as stream:
            name = stream.name
            os.chmod(name, 0o600)
            json.dump(state, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def usage_values(rx, tx):
    return {"upload_bytes": rx, "download_bytes": tx, "total_bytes": rx + tx,
            "upload_gb": f"{Decimal(rx) / Decimal(1_000_000_000):.6f}",
            "download_gb": f"{Decimal(tx) / Decimal(1_000_000_000):.6f}",
            "total_gb": f"{Decimal(rx + tx) / Decimal(1_000_000_000):.6f}"}


def make_report(state, port, zone="UTC"):
    tz = report_timezone(zone)
    entry = state["ports"][port]
    now = timestamp(state["last_sync"] or entry["since"])
    epoch = int(now.timestamp())
    local_midnight = now.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0, fold=0)
    starts = [("today", int(local_midnight.timestamp())),
              ("last_24_hours", (epoch - 86400) // BUCKET_SECONDS * BUCKET_SECONDS),
              ("last_7_days", (epoch - 7 * 86400) // BUCKET_SECONDS * BUCKET_SECONDS),
              ("last_30_days", (epoch - 30 * 86400) // BUCKET_SECONDS * BUCKET_SECONDS)]
    history = entry.get("history", history_start(now.isoformat(timespec="seconds")))
    coverage = max(int(timestamp(history["since"]).timestamp()), history["retained_since"])
    rows = []
    for key, start in starts:
        rx = tx = 0
        for minute, upload, download in history["buckets"]:
            if start // BUCKET_SECONDS * BUCKET_SECONDS <= minute <= epoch:
                rx += upload
                tx += download
        reasons = []
        status = "complete"
        if coverage > start:
            status = "partial"
            reasons.append("History does not cover the entire period")
        if any(left <= epoch and right >= start for left, right in history["gaps"]):
            status = "incomplete"
            reasons.append("Sampling gap, clock change, or counter recovery overlaps this period")
        rows.append({"key": key, "start": iso(start), "end": iso(epoch),
                     **usage_values(rx, tx), "status": status, "reasons": reasons})
    rows.append({"key": "all_time", "start": entry["since"], "end": iso(epoch),
                 **usage_values(entry["rx_bytes"], entry["tx_bytes"]),
                 "status": "incomplete" if state["events"] else "recorded",
                 "reasons": ["Accounting recovery warnings exist"] if state["events"] else []})
    return {"port": int(port), "interface": state["interface"],
            "since": entry["since"], "updated": state["last_sync"],
            **usage_values(entry["rx_bytes"], entry["tx_bytes"]),
            "timezone": zone, "bucket_seconds": BUCKET_SECONDS,
            "history_since": history["since"], "retained_since": iso(history["retained_since"]),
            "history_pruning_suspended": state.get("history_pruning_suspended", False),
            "periods": rows, "warnings": state["events"]}


def run(command, input_text=None):
    result = subprocess.run(command, input=input_text, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


class Meter:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / "state.json"
        self.nft = shutil.which("nft")
        if not self.nft:
            raise RuntimeError("nft not installed; install the Ubuntu nftables package first")

    def snapshot(self):
        tables = json.loads(run([self.nft, "-j", "list", "tables"]))["nftables"]
        exists = any(obj.get("table", {}).get("family") == "inet" and
                     obj.get("table", {}).get("name") == TABLE for obj in tables)
        if not exists:
            return None
        return parse_snapshot(json.loads(run([self.nft, "-j", "list", "table", "inet", TABLE])))

    def transaction(self, script):
        run([self.nft, "--check", "-f", "-"], script)
        run([self.nft, "-f", "-"], script)

    def port_rules(self, port, interface):
        return (
            f'add counter inet {TABLE} p{port}_rx\n'
            f'add counter inet {TABLE} p{port}_tx\n'
            f'add rule inet {TABLE} incoming iifname "{interface}" meta l4proto {{ tcp, udp }} '
            f'th dport {port} counter name p{port}_rx comment "port-traffic:{port}:rx"\n'
            f'add rule inet {TABLE} outgoing oifname "{interface}" meta l4proto {{ tcp, udp }} '
            f'th sport {port} counter name p{port}_tx comment "port-traffic:{port}:tx"\n'
        )

    def ensure(self, state):
        snap = self.snapshot()
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if snap is None:
            reason = "boot changed" if state["boot_id"] != boot_id else "kernel table removed externally"
            state = new_generation(state, uuid.uuid4().hex, boot_id, reason)
            # Persist the new epoch before kernel installation, so a crash cannot add an old epoch twice.
            save_state(self.path, state)
            script = (f'add table inet {TABLE} {{ comment "{PREFIX}{state["generation"]}"; }}\n'
                      f'add chain inet {TABLE} incoming {{ type filter hook input priority -150; policy accept; }}\n'
                      f'add chain inet {TABLE} outgoing {{ type filter hook output priority -150; policy accept; }}\n')
            for port in state["ports"]:
                script += self.port_rules(port, state["interface"])
            self.transaction(script)
            snap = self.snapshot()
        if snap["generation"] != state["generation"]:
            raise ValueError("Foreign or stale table generation: refusing to rebuild or change balances")
        pending = [port for port, entry in state["ports"].items() if entry.get("pending")]
        for port in pending:
            present = [f"p{port}_{d}" in snap["counters"] for d in ("rx", "tx")]
            if not any(present):
                self.transaction(self.port_rules(port, state["interface"]))
            elif not all(present):
                raise ValueError(f"Partially installed port {port}; refusing ambiguous accounting")
            state["ports"][port]["pending"] = False
        if pending:
            save_state(self.path, state)
            snap = self.snapshot()
        if state["boot_id"] != boot_id:
            self.check_rules(state, snap)
            state = copy.deepcopy(state)
            for port, entry in state["ports"].items():
                for direction in ("rx", "tx"):
                    entry[f"raw_{direction}"] = byte_count(snap["counters"][f"p{port}_{direction}"])
            state["boot_id"] = boot_id
            state["last_monotonic_ns"] = None
            now = utcnow()
            recovery_gap(state, now)
            record_event(state, "boot_rebase",
                         "boot changed with existing counters; restored values were not charged; "
                         "traffic before this baseline may be missing", now)
            save_state(self.path, state)
        return state, snap

    def check_rules(self, state, snap):
        for name, hook in (("incoming", "input"), ("outgoing", "output")):
            chain = snap["chains"].get(name, {})
            if chain.get("hook") != hook or chain.get("prio") != -150 or chain.get("policy") != "accept":
                raise ValueError(f"Meter chain {name} was modified; inspect nft list table inet {TABLE}")
        expected = {f"port-traffic:{p}:{d}" for p in state["ports"] for d in ("rx", "tx")}
        actual = [rule.get("comment") for rule in snap["rules"]]
        if set(actual) != expected or len(actual) != len(expected):
            raise ValueError("Meter rules changed or duplicated; refusing to report an unreliable total")
        for rule in snap["rules"]:
            _, port, direction = rule["comment"].split(":")
            incoming = direction == "rx"
            chain = "incoming" if incoming else "outgoing"
            interface_key = "iifname" if incoming else "oifname"
            port_key = "dport" if incoming else "sport"
            expressions = [
                {"match": {"op": "==", "left": {"meta": {"key": interface_key}}, "right": state["interface"]}},
                {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": port_key}}, "right": int(port)}},
                {"counter": f"p{port}_{direction}"},
            ]
            if rule.get("chain") != chain or rule.get("expr") != expressions:
                raise ValueError(f"Meter rule for {port}/{direction} was modified; refusing inaccurate accounting")

    def sync(self):
        if not self.path.exists():
            return None
        state = read_state(self.path)
        state, snap = self.ensure(state)
        self.check_rules(state, snap)
        state = apply_sample(state, snap, utcnow(), monotonic_ns=time.monotonic_ns())
        save_state(self.path, state)
        return state

    def add(self, port, interface=None):
        port = valid_port(port)
        if self.path.exists():
            state = self.sync()
            if interface is not None and interface != state["interface"]:
                raise ValueError(f"Meter already uses {state['interface']}; do not change interface mid-billing")
        else:
            if interface is None:
                routes = json.loads(run(["ip", "-j", "-4", "route", "show", "default"]))
                devices = sorted({route["dev"] for route in routes if "dev" in route})
                if len(devices) != 1:
                    raise ValueError("Cannot choose one WAN interface; pass --interface NAME")
                interface = devices[0]
            interface = valid_interface(interface)
            if not (Path("/sys/class/net") / interface).exists():
                raise ValueError(f"Interface {interface} does not exist")
            state = {"version": 2, "generation": None, "boot_id": None,
                     "interface": interface, "ports": {}, "last_sync": None,
                     "last_monotonic_ns": None, "history_pruning_suspended": False, "events": []}
            save_state(self.path, state)
            state, _ = self.ensure(state)
        if port in state["ports"]:
            return state
        now = utcnow()
        state["ports"][port] = {"since": now, "rx_bytes": 0, "tx_bytes": 0,
                                "raw_rx": 0, "raw_tx": 0, "pending": True,
                                "history": history_start(now)}
        # Commit intent first; ensure() can finish an interrupted kernel transaction idempotently.
        save_state(self.path, state)
        return self.sync()


def use_color(mode):
    if mode != "auto":
        return mode == "always"
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"


def print_reports(state, port, as_json, zone="UTC", color="auto"):
    if state is None or not state["ports"]:
        raise ValueError("No tracked ports. Start with: port-traffic add PORT")
    if port and port not in state["ports"]:
        raise ValueError(f"Port {port} is not tracked. Run: port-traffic add {port}")
    ports = [port] if port else sorted(state["ports"], key=int)
    reports = [make_report(state, p, zone) for p in ports]
    if as_json:
        print(json.dumps(reports[0] if port else reports, indent=2))
        return
    colored = use_color(color)
    def paint(text, code):
        return f"\x1b[{code}m{text}\x1b[0m" if colored else text
    labels = ("Today", "Last 24 hours", "Last 7 days", "Last 30 days", "All time")
    headers = ("Period", "Download (GB)", "Upload (GB)", "Total (GB)", "History")
    for report in reports:
        print(paint("PORTLEDGER / TRAFFIC REPORT", "1"))
        print(f"Port {report['port']} | TCP + UDP | IPv4 + IPv6 | {report['interface']}")
        updated = timestamp(report["updated"] or report["since"]).astimezone(report_timezone(zone))
        print(f"Updated: {updated.isoformat(timespec='seconds')} | Timezone: {zone}")
        rows = [[label, row["download_gb"], row["upload_gb"], row["total_gb"], row["status"].title()]
                for label, row in zip(labels, report["periods"])]
        widths = [max(len(header), *(len(row[i]) for row in rows)) for i, header in enumerate(headers)]
        border = "+-" + "-+-".join("-" * width for width in widths) + "-+"
        def table_row(values, codes):
            cells = [value.rjust(widths[i]) if i in (1, 2, 3) else value.ljust(widths[i])
                     for i, value in enumerate(values)]
            return "| " + " | ".join(paint(cell, code) if code else cell for cell, code in zip(cells, codes)) + " |"
        print(border)
        print(table_row(headers, ["1"] * 5))
        print(border)
        for index, row in enumerate(rows):
            if index == 4:
                print(border)
            status_color = "33" if row[4] in ("Partial", "Incomplete") else "32"
            print(table_row(row, ["1" if index == 4 else None, "36", "35", "1;32", status_color]))
        print(border)
        print(f"All-time since (UTC): {report['since']} | Exact total bytes: {report['total_bytes']}")
        print(f"History since (UTC): {report['history_since']}")
        print("Download: server -> client | Upload: client -> server | 1 GB = 1,000,000,000 bytes.")
        print("Today: local midnight | Last 30 days: rolling month | Period resolution: 1 minute.")
        print("Partial: not enough history. Incomplete: gaps or recovery; period attribution is uncertain.")
        print("Recent usage is assigned to observation minutes, not exact packet times; IP headers/retries count.")
        if report["history_pruning_suspended"]:
            print(paint("WARNING: History pruning suspended after a clock change; retained history may exceed 31 days.", "33"))
        if report["warnings"]:
            print(paint(f"WARNING: {len(report['warnings'])} accounting event(s); completeness is not guaranteed.", "33"))
            for event in report["warnings"][-3:]:
                print(f"  {event['time']}: {event['kind']}: {event['detail']}")
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog="Shortcut: port-traffic 40199")
    parser.add_argument("--state-dir", default=DEFAULT_DIR)
    parser.set_defaults(timezone="UTC", color="auto")
    sub = parser.add_subparsers(dest="command")
    add = sub.add_parser("add", help="Start tracking a port; repeat calls never reset its balance")
    add.add_argument("port")
    add.add_argument("--interface", type=valid_interface)
    reports = [add]
    for command in ("show", "list"):
        show = sub.add_parser(command, help="Read and save live usage with period history")
        show.add_argument("port", nargs="?")
        show.add_argument("--json", action="store_true")
        reports.append(show)
    for report in reports:
        report.add_argument("--timezone", default="UTC", help="IANA timezone for Today (default: UTC)")
        report.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                            help="ANSI colors: auto respects NO_COLOR and TERM=dumb")
    for command in ("sync", "restore", "doctor"):
        sub.add_parser(command)
    args_list = list(sys.argv[1:] if argv is None else argv)
    index = 2 if args_list[:1] == ["--state-dir"] else 0
    if index < len(args_list) and re.fullmatch(r"[0-9]+", args_list[index]):
        args_list.insert(index, "show")
    if not args_list:
        args_list = ["show"]
    args = parser.parse_args(args_list)
    if hasattr(args, "timezone"):
        report_timezone(args.timezone)
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Run as root (or use sudo); nftables counters require CAP_NET_ADMIN")
    import fcntl
    directory = Path(args.state_dir)
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    with (directory / "lock").open("a") as lock:
        os.chmod(directory / "lock", 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        meter = Meter(directory)
        if args.command == "add":
            state = meter.add(args.port, args.interface)
            print_reports(state, valid_port(args.port), False, args.timezone, args.color)
        elif args.command in ("show", "list", None):
            port = valid_port(args.port) if getattr(args, "port", None) else None
            print_reports(meter.sync(), port, getattr(args, "json", False), args.timezone, args.color)
        else:
            state = meter.sync()
            if args.command == "doctor":
                if state is None:
                    raise ValueError("Not initialized: port-traffic add PORT")
                print(f"OK: {len(state['ports'])} ports; interface {state['interface']}; rules and counters present")
                print(f"State: {meter.path}; last live checkpoint: {state['last_sync']}")
                print(f"Accounting warnings: {len(state['events'])}")
                for event in state["events"]:
                    print(f"{event['time']} {event['kind']}: {event['detail']}")
                if state["events"]:
                    return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
