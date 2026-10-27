#!/usr/bin/python3
"""Persistent, non-filtering per-port nftables accounting for local listeners."""
from __future__ import annotations

import argparse
from bisect import bisect_left
import copy
from datetime import datetime, timezone
from decimal import Decimal
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
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


class PortLedgerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, state_dir, default_zone="Asia/Tehran"):
        super().__init__(server_address, RequestHandlerClass)
        self.state_dir = Path(state_dir)
        self.default_zone = default_zone

    def get_state(self):
        path = self.state_dir / "state.json"
        if not path.is_file():
            raise FileNotFoundError(f"State file not found: {path}")
        return read_state(path)


class WebHandler(BaseHTTPRequestHandler):
    server_version = "PortLedger/1.0"

    def log_message(self, format, *args):
        pass

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if getattr(self, "command", "") != "HEAD":
            self.wfile.write(body)

    def send_html(self, status, html_content):
        body = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        if getattr(self, "command", "") != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(parsed.query)

        if not path.startswith("/api/"):
            if path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            self.send_html(200, DASHBOARD_HTML)
            return

        if path == "/api/health":
            try:
                state = self.server.get_state()
                self.send_json(200, {
                    "status": "ok",
                    "interface": state.get("interface", ""),
                    "ports_count": len(state.get("ports", {})),
                    "last_sync": state.get("last_sync"),
                })
            except Exception:
                self.send_json(503, {"status": "error", "message": "State file unavailable"})
            return

        try:
            state = self.server.get_state()
        except Exception:
            self.send_json(503, {"error": "State file unavailable"})
            return

        zone = query.get("zone", [self.server.default_zone])[0]
        try:
            report_timezone(zone)
        except ValueError as e:
            self.send_json(400, {"error": str(e)})
            return

        if path == "/api/overview":
            ports = sorted(state.get("ports", {}).keys(), key=lambda p: int(p))
            total_rx = 0
            total_tx = 0
            for p in ports:
                entry = state["ports"][p]
                total_rx += entry.get("rx_bytes", 0)
                total_tx += entry.get("tx_bytes", 0)
            uv = usage_values(total_rx, total_tx)
            self.send_json(200, {
                "interface": state.get("interface", ""),
                "last_sync": state.get("last_sync"),
                "ports": ports,
                "total_bytes": uv["total_bytes"],
                "total_gb": uv["total_gb"],
                "download_bytes": uv["download_bytes"],
                "download_gb": uv["download_gb"],
                "upload_bytes": uv["upload_bytes"],
                "upload_gb": uv["upload_gb"],
            })
            return

        if path == "/api/ports":
            ports = sorted(state.get("ports", {}).keys(), key=lambda p: int(p))
            result = []
            for p in ports:
                report = make_report(state, p, zone)
                result.append(report)
            self.send_json(200, result)
            return

        if path.startswith("/api/ports/"):
            subpath = path[len("/api/ports/"):]
            parts = subpath.split("/")
            port_str = parts[0]
            try:
                port_valid = valid_port(port_str)
            except ValueError as e:
                self.send_json(400, {"error": f"Invalid port: {port_str}"})
                return

            if port_valid not in state.get("ports", {}):
                self.send_json(404, {"error": f"Port {port_valid} not tracked"})
                return

            if len(parts) == 1:
                report = make_report(state, port_valid, zone)
                self.send_json(200, report)
                return
            elif len(parts) == 2 and parts[1] == "history":
                entry = state["ports"][port_valid]
                hist = entry.get("history", {})
                buckets_raw = hist.get("buckets", [])
                buckets = []
                for b in buckets_raw:
                    epoch, rx, tx = b[0], b[1], b[2]
                    buckets.append({
                        "epoch": epoch,
                        "timestamp": datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds"),
                        "upload_bytes": rx,
                        "download_bytes": tx,
                        "total_bytes": rx + tx,
                    })
                self.send_json(200, {
                    "port": port_valid,
                    "retained_since": hist.get("retained_since"),
                    "buckets": buckets,
                })
                return

        self.send_json(404, {"error": "Not found"})


def create_web_server(state_dir, host="127.0.0.1", port=9090, default_zone="Asia/Tehran"):
    return PortLedgerServer((host, port), WebHandler, state_dir=state_dir, default_zone=default_zone)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PortLedger • دیده‌بان ترافیک پورت‌ها</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #0B0F19;
      --bg-surface: #111827;
      --bg-surface-elevated: #1F2937;
      --bg-surface-card: rgba(17, 24, 39, 0.75);
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-active: rgba(56, 189, 248, 0.4);
      --text-primary: #F9FAFB;
      --text-secondary: #9CA3AF;
      --text-muted: #6B7280;
      --accent-cyan: #38BDF8;
      --accent-cyan-glow: rgba(56, 189, 248, 0.15);
      --accent-emerald: #10B981;
      --accent-emerald-glow: rgba(16, 185, 129, 0.15);
      --accent-violet: #A78BFA;
      --accent-violet-glow: rgba(167, 139, 250, 0.15);
      --status-ok: #10B981;
      --status-warn: #F59E0B;
      --status-error: #EF4444;
      --font-fa: 'Vazirmatn', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
      --radius-sm: 8px;
      --radius-md: 12px;
      --radius-lg: 18px;
      --shadow-card: 0 4px 20px -2px rgba(0, 0, 0, 0.5), 0 0 0 1px var(--border-subtle);
      --shadow-glow: 0 0 25px -5px rgba(56, 189, 248, 0.25);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-base);
      color: var(--text-primary);
      font-family: var(--font-fa);
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
      background-image:
        radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.08) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.06) 0px, transparent 50%),
        radial-gradient(at 50% 50%, rgba(16, 185, 129, 0.04) 0px, transparent 60%);
      background-attachment: fixed;
    }

    .container {
      width: 100%;
      max-width: 1280px;
      margin: 0 auto;
      padding: 24px 20px 48px;
    }

    header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border-subtle);
      margin-bottom: 32px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .brand-icon {
      width: 44px;
      height: 44px;
      border-radius: var(--radius-md);
      background: linear-gradient(135deg, #0284C7, #4F46E5);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px rgba(2, 132, 199, 0.4);
    }

    .brand-icon svg {
      width: 24px;
      height: 24px;
      stroke: #fff;
    }

    .brand-text h1 {
      font-size: 1.35rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-badge {
      font-size: 0.75rem;
      font-family: var(--font-mono);
      padding: 2px 8px;
      background: rgba(56, 189, 248, 0.12);
      color: var(--accent-cyan);
      border-radius: 999px;
      border: 1px solid rgba(56, 189, 248, 0.3);
    }

    .brand-subtitle {
      font-size: 0.85rem;
      color: var(--text-secondary);
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .control-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 0.85rem;
      color: var(--text-secondary);
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: var(--status-ok);
      box-shadow: 0 0 10px var(--status-ok);
      animation: pulse 2s infinite ease-in-out;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }

    .select-tz {
      background: var(--bg-surface);
      color: var(--text-primary);
      border: 1px solid var(--border-subtle);
      padding: 8px 14px;
      border-radius: var(--radius-sm);
      font-family: var(--font-fa);
      font-size: 0.85rem;
      cursor: pointer;
      outline: none;
      transition: all 0.2s;
    }

    .select-tz:hover, .select-tz:focus {
      border-color: var(--accent-cyan);
    }

    .btn-action {
      display: flex;
      align-items: center;
      gap: 6px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      color: var(--text-primary);
      padding: 8px 16px;
      border-radius: var(--radius-sm);
      font-family: var(--font-fa);
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn-action:hover {
      background: var(--bg-surface-elevated);
      border-color: var(--border-active);
    }

    .btn-action.spinning svg {
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      100% { transform: rotate(-360deg); }
    }

    /* KPI Summary Cards Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 20px;
      margin-bottom: 36px;
    }

    .kpi-card {
      background: var(--bg-surface-card);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 22px 24px;
      box-shadow: var(--shadow-card);
      position: relative;
      overflow: hidden;
      transition: transform 0.2s, border-color 0.2s;
    }

    .kpi-card:hover {
      transform: translateY(-2px);
      border-color: rgba(255, 255, 255, 0.16);
    }

    .kpi-card::before {
      content: "";
      position: absolute;
      top: 0;
      right: 0;
      width: 100%;
      height: 3px;
    }

    .kpi-card.cyan::before { background: linear-gradient(90deg, var(--accent-cyan), transparent); }
    .kpi-card.emerald::before { background: linear-gradient(90deg, var(--accent-emerald), transparent); }
    .kpi-card.violet::before { background: linear-gradient(90deg, var(--accent-violet), transparent); }
    .kpi-card.slate::before { background: linear-gradient(90deg, #64748B, transparent); }

    .kpi-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
    }

    .kpi-title {
      font-size: 0.9rem;
      font-weight: 500;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .kpi-icon-wrap {
      width: 34px;
      height: 34px;
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .cyan .kpi-icon-wrap { background: var(--accent-cyan-glow); color: var(--accent-cyan); }
    .emerald .kpi-icon-wrap { background: var(--accent-emerald-glow); color: var(--accent-emerald); }
    .violet .kpi-icon-wrap { background: var(--accent-violet-glow); color: var(--accent-violet); }
    .slate .kpi-icon-wrap { background: rgba(100, 116, 139, 0.15); color: #94A3B8; }

    .kpi-value-row {
      display: flex;
      align-items: baseline;
      gap: 10px;
    }

    .kpi-value {
      font-family: var(--font-mono);
      font-size: 2rem;
      font-weight: 700;
      color: var(--text-primary);
      letter-spacing: -0.03em;
    }

    .kpi-unit {
      font-size: 1rem;
      font-weight: 600;
      color: var(--text-secondary);
    }

    .kpi-subtext {
      margin-top: 8px;
      font-size: 0.8rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }

    /* Port Nav Tabs */
    .tabs-section {
      margin-bottom: 24px;
    }

    .tabs-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
    }

    .section-title {
      font-size: 1.15rem;
      font-weight: 700;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .port-tabs-list {
      display: flex;
      gap: 10px;
      overflow-x: auto;
      padding-bottom: 6px;
    }

    .port-tab {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      padding: 10px 18px;
      border-radius: var(--radius-md);
      font-family: var(--font-fa);
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      white-space: nowrap;
      transition: all 0.2s;
    }

    .port-tab:hover {
      background: var(--bg-surface-elevated);
      color: var(--text-primary);
    }

    .port-tab.active {
      background: rgba(56, 189, 248, 0.12);
      border-color: var(--accent-cyan);
      color: var(--accent-cyan);
      box-shadow: 0 0 15px rgba(56, 189, 248, 0.2);
    }

    .tab-badge {
      font-family: var(--font-mono);
      font-size: 0.75rem;
      padding: 1px 6px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 999px;
    }

    /* Port Detail Box */
    .port-detail-card {
      background: var(--bg-surface-card);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-card);
      margin-bottom: 30px;
      overflow: hidden;
    }

    .port-detail-header {
      padding: 20px 24px;
      background: rgba(31, 41, 55, 0.4);
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }

    .port-title-meta {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .port-number-badge {
      font-family: var(--font-mono);
      font-size: 1.3rem;
      font-weight: 700;
      background: #0284C7;
      color: #fff;
      padding: 6px 14px;
      border-radius: var(--radius-sm);
      letter-spacing: 0.05em;
    }

    .port-info-meta {
      display: flex;
      flex-direction: column;
    }

    .port-since {
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    /* Table styling */
    .table-container {
      width: 100%;
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: right;
      font-size: 0.9rem;
    }

    th {
      background: rgba(17, 24, 39, 0.95);
      color: var(--text-secondary);
      font-weight: 600;
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-subtle);
      white-space: nowrap;
    }

    td {
      padding: 16px 20px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
      vertical-align: middle;
    }

    tr:last-child td {
      border-bottom: none;
    }

    tr.highlight-all-time {
      background: rgba(56, 189, 248, 0.04);
      font-weight: 600;
    }

    .period-name {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 600;
    }

    .period-icon {
      color: var(--text-muted);
    }

    .num-cell {
      font-family: var(--font-mono);
      font-size: 0.95rem;
    }

    .download-val { color: var(--accent-emerald); }
    .upload-val { color: var(--accent-violet); }
    .total-val { color: var(--accent-cyan); font-weight: 700; }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.78rem;
      padding: 4px 10px;
      border-radius: 999px;
      font-weight: 500;
    }

    .status-badge.complete {
      background: rgba(16, 185, 129, 0.12);
      color: var(--status-ok);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .status-badge.partial {
      background: rgba(245, 158, 11, 0.12);
      color: var(--status-warn);
      border: 1px solid rgba(245, 158, 11, 0.3);
    }

    .status-badge.incomplete {
      background: rgba(239, 68, 68, 0.12);
      color: var(--status-error);
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    /* History Chart Section */
    .chart-section {
      padding: 24px;
      border-top: 1px solid var(--border-subtle);
      background: rgba(17, 24, 39, 0.4);
    }

    .chart-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }

    .chart-title {
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .chart-legend {
      display: flex;
      align-items: center;
      gap: 16px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .legend-color {
      width: 10px;
      height: 10px;
      border-radius: 2px;
    }

    .chart-wrapper {
      position: relative;
      height: 180px;
      width: 100%;
      background: rgba(11, 15, 25, 0.6);
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
      padding: 12px;
      display: flex;
      align-items: flex-end;
      gap: 4px;
      overflow-x: auto;
    }

    .chart-bar-container {
      flex: 1;
      height: 100%;
      min-width: 6px;
      max-width: 24px;
      display: flex;
      flex-direction: column;
      justify-content: flex-end;
      position: relative;
      cursor: pointer;
    }

    .chart-bar-segment {
      width: 100%;
      transition: height 0.3s ease;
    }

    .chart-bar-segment.dl {
      background: var(--accent-emerald);
      border-radius: 2px 2px 0 0;
    }

    .chart-bar-segment.ul {
      background: var(--accent-violet);
    }

    .chart-bar-container:hover .chart-bar-segment {
      filter: brightness(1.3);
    }

    .chart-tooltip {
      position: absolute;
      bottom: calc(100% + 8px);
      left: 50%;
      transform: translateX(-50%);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      border-radius: var(--radius-sm);
      padding: 8px 12px;
      font-size: 0.75rem;
      white-space: nowrap;
      pointer-events: none;
      z-index: 100;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.15s, visibility 0.15s;
    }

    .chart-bar-container:hover .chart-tooltip {
      opacity: 1;
      visibility: visible;
    }

    .chart-empty {
      width: 100%;
      height: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-muted);
      font-size: 0.85rem;
    }

    footer {
      margin-top: auto;
      padding: 24px 0 12px;
      border-top: 1px solid var(--border-subtle);
      text-align: center;
      font-size: 0.82rem;
      color: var(--text-muted);
    }

    .footer-links {
      display: flex;
      justify-content: center;
      gap: 16px;
      margin-bottom: 8px;
    }

    .footer-links a {
      color: var(--text-secondary);
      text-decoration: none;
      transition: color 0.2s;
    }

    .footer-links a:hover {
      color: var(--accent-cyan);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="brand-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
          </svg>
        </div>
        <div class="brand-text">
          <h1>PortLedger <span class="brand-badge">دیده‌بان ترافیک</span></h1>
          <div class="brand-subtitle">پایش مداوم و تفکیکی مصرف ترافیک پورت‌ها با کارایی nftables</div>
        </div>
      </div>

      <div class="header-controls">
        <div class="control-pill">
          <div class="status-dot"></div>
          <span id="header-status">متصل به سرویس</span>
        </div>
        <div class="control-pill">
          <span>رابط:</span>
          <strong id="header-interface" style="font-family: var(--font-mono); color: var(--accent-cyan)">-</strong>
        </div>
        <select id="tz-select" class="select-tz" title="انتخاب منطقه زمانی">
          <option value="Asia/Tehran" selected>تهران (Asia/Tehran)</option>
          <option value="UTC">گرینویچ (UTC)</option>
          <option value="Europe/Istanbul">استانبول (Europe/Istanbul)</option>
          <option value="Europe/Berlin">برلین (Europe/Berlin)</option>
        </select>
        <button id="btn-refresh" class="btn-action" title="بروزرسانی داده‌ها">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
          </svg>
          <span>تازه&zwnj;سازی</span>
        </button>
      </div>
    </header>

    <!-- Global KPIs -->
    <div class="kpi-grid">
      <div class="kpi-card cyan">
        <div class="kpi-header">
          <span class="kpi-title">مجموع ترافیک پورت‌های تحت پایش</span>
          <div class="kpi-icon-wrap">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
          </div>
        </div>
        <div class="kpi-value-row">
          <span id="kpi-total-gb" class="kpi-value">0.00</span>
          <span class="kpi-unit">گیگابایت</span>
        </div>
        <div id="kpi-total-bytes" class="kpi-subtext">0 بایت</div>
      </div>

      <div class="kpi-card emerald">
        <div class="kpi-header">
          <span class="kpi-title">دانلود پورت‌های پایش‌شده (ارسال سرور)</span>
          <div class="kpi-icon-wrap">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
          </div>
        </div>
        <div class="kpi-value-row">
          <span id="kpi-dl-gb" class="kpi-value">0.00</span>
          <span class="kpi-unit">گیگابایت</span>
        </div>
        <div id="kpi-dl-bytes" class="kpi-subtext">0 بایت</div>
      </div>

      <div class="kpi-card violet">
        <div class="kpi-header">
          <span class="kpi-title">آپلود پورت‌های پایش‌شده (دریافت سرور)</span>
          <div class="kpi-icon-wrap">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
          </div>
        </div>
        <div class="kpi-value-row">
          <span id="kpi-ul-gb" class="kpi-value">0.00</span>
          <span class="kpi-unit">گیگابایت</span>
        </div>
        <div id="kpi-ul-bytes" class="kpi-subtext">0 بایت</div>
      </div>

      <div class="kpi-card slate">
        <div class="kpi-header">
          <span class="kpi-title">پورت‌های تحت پایش</span>
          <div class="kpi-icon-wrap">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
          </div>
        </div>
        <div class="kpi-value-row">
          <span id="kpi-ports-count" class="kpi-value">0</span>
          <span class="kpi-unit">پورت</span>
        </div>
        <div id="kpi-last-sync" class="kpi-subtext">آخرین بررسی: در انتظار داده</div>
      </div>
    </div>

    <!-- Port Tabs -->
    <div class="tabs-section">
      <div class="tabs-header">
        <div class="section-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
          <span>تفکیک مصرف پورت‌ها</span>
        </div>
      </div>
      <div id="port-tabs-container" class="port-tabs-list">
        <button class="port-tab active" data-port="all">همه پورت‌ها</button>
      </div>
    </div>

    <!-- Port Cards Container -->
    <div id="ports-details-container">
      <div style="text-align:center; padding: 48px; color: var(--text-muted);">در حال دریافت داده‌های حسابداری...</div>
    </div>

    <footer>
      <div class="footer-links">
        <a href="/api/overview" target="_blank">خلاصه API</a>
        <span>•</span>
        <a href="/api/ports" target="_blank">لیست کامل پورت‌ها (JSON)</a>
        <span>•</span>
        <a href="/api/health" target="_blank">سلامت سیستم</a>
      </div>
      <div>PortLedger • سیستم سنجش دقیق ترافیک شبکه با پایگاه امن nftables</div>
    </footer>
  </div>

  <script>
    const PERIOD_LABELS = {
      'today': 'امروز (از بامداد محلی)',
      'last_24_hours': '24 ساعت گذشته',
      'last_7_days': '7 روز گذشته',
      'last_30_days': '30 روز گذشته',
      'all_time': 'از ابتدای پایش'
    };

    const STATUS_MAP = {
      'complete': { label: 'کامل', class: 'complete' },
      'partial': { label: 'بخشی', class: 'partial' },
      'incomplete': { label: 'ناقص (وقفه/تغییر ساعت)', class: 'incomplete' }
    };

    function formatGB(val) {
      if (val === null || val === undefined || val === '') return '0.00';
      const num = Number(val);
      return isNaN(num) ? '0.00' : num.toFixed(2);
    }

    function formatNumber(num) {
      if (num === null || num === undefined) return '0';
      return new Intl.NumberFormat('en-US').format(num);
    }

    let currentSelectedPort = 'all';
    let allPortsData = [];
    let overviewData = null;

    async function fetchData() {
      const btn = document.getElementById('btn-refresh');
      btn.classList.add('spinning');
      const tz = document.getElementById('tz-select').value;

      try {
        const [overviewRes, portsRes] = await Promise.all([
          fetch('/api/overview'),
          fetch(`/api/ports?zone=${encodeURIComponent(tz)}`)
        ]);

        if (!overviewRes.ok || !portsRes.ok) throw new Error('خطا در دریافت اطلاعات');

        overviewData = await overviewRes.json();
        allPortsData = await portsRes.json();

        renderOverview(overviewData);
        renderTabs(allPortsData);
        renderPorts(allPortsData);
        document.getElementById('header-status').textContent = 'متصل و فعال';
      } catch (err) {
        console.error(err);
        document.getElementById('header-status').textContent = 'خطای اتصال';
      } finally {
        btn.classList.remove('spinning');
      }
    }

    function renderOverview(data) {
      document.getElementById('header-interface').textContent = data.interface || 'eth0';
      document.getElementById('kpi-total-gb').textContent = formatGB(data.total_gb);
      document.getElementById('kpi-total-bytes').textContent = formatNumber(data.total_bytes) + ' بایت';

      document.getElementById('kpi-dl-gb').textContent = formatGB(data.download_gb);
      document.getElementById('kpi-dl-bytes').textContent = formatNumber(data.download_bytes) + ' بایت';

      document.getElementById('kpi-ul-gb').textContent = formatGB(data.upload_gb);
      document.getElementById('kpi-ul-bytes').textContent = formatNumber(data.upload_bytes) + ' بایت';

      document.getElementById('kpi-ports-count').textContent = formatNumber(data.ports ? data.ports.length : 0);
      if (data.last_sync) {
        const d = new Date(data.last_sync);
        document.getElementById('kpi-last-sync').textContent = 'آخرین ثبت: ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      }
    }

    function renderTabs(ports) {
      const container = document.getElementById('port-tabs-container');
      let html = `<button class="port-tab ${currentSelectedPort === 'all' ? 'active' : ''}" onclick="selectPort('all')">همه پورت‌ها</button>`;
      for (const p of ports) {
        const activeClass = currentSelectedPort === String(p.port) ? 'active' : '';
        html += `<button class="port-tab ${activeClass}" onclick="selectPort('${p.port}')">
          پورت ${p.port}
          <span class="tab-badge">${formatGB(p.total_gb)} GB</span>
        </button>`;
      }
      container.innerHTML = html;
    }

    function selectPort(port) {
      currentSelectedPort = String(port);
      renderTabs(allPortsData);
      renderPorts(allPortsData);
    }

    async function loadPortHistory(port, chartEl) {
      try {
        const res = await fetch(`/api/ports/${port}/history`);
        if (!res.ok) return;
        const data = await res.json();
        const buckets = data.buckets || [];
        if (buckets.length === 0) {
          chartEl.innerHTML = '<div class="chart-empty">تاریخچه اخیر هنوز ثبت نشده است</div>';
          return;
        }

        // Find max total
        let maxVal = 1;
        for (const b of buckets) {
          if (b.total_bytes > maxVal) maxVal = b.total_bytes;
        }

        let barsHtml = '';
        for (const b of buckets) {
          const dlPct = (b.download_bytes / maxVal) * 100;
          const ulPct = (b.upload_bytes / maxVal) * 100;
          const timeStr = new Date(b.epoch * 1000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
          const dlKb = (b.download_bytes / 1000).toFixed(2);
          const ulKb = (b.upload_bytes / 1000).toFixed(2);

          barsHtml += `
            <div class="chart-bar-container">
              <div class="chart-tooltip">
                <strong>ساعت: ${timeStr}</strong><br>
                دریافت (دانلود): ${dlKb} KB<br>
                ارسال (آپلود): ${ulKb} KB
              </div>
              <div class="chart-bar-segment ul" style="height: ${ulPct}%;"></div>
              <div class="chart-bar-segment dl" style="height: ${dlPct}%;"></div>
            </div>
          `;
        }
        chartEl.innerHTML = barsHtml;
      } catch (e) {
        chartEl.innerHTML = '<div class="chart-empty">خطا در بارگذاری نمودار</div>';
      }
    }

    function renderPorts(ports) {
      const container = document.getElementById('ports-details-container');
      const filtered = currentSelectedPort === 'all'
        ? ports
        : ports.filter(p => String(p.port) === currentSelectedPort);

      if (filtered.length === 0) {
        container.innerHTML = '<div style="text-align:center; padding: 40px; color: var(--text-muted);">هیچ پورتی یافت نشد.</div>';
        return;
      }

      let html = '';
      for (const p of filtered) {
        let rowsHtml = '';
        for (let i = 0; i < p.periods.length; i++) {
          const r = p.periods[i];
          const isAllTime = r.key === 'all_time';
          const st = STATUS_MAP[r.status] || { label: r.status, class: 'partial' };
          const periodName = PERIOD_LABELS[r.key] || r.label;

          rowsHtml += `
            <tr class="${isAllTime ? 'highlight-all-time' : ''}">
              <td>
                <div class="period-name">
                  <span class="period-icon">●</span>
                  <span>${periodName}</span>
                </div>
              </td>
              <td class="num-cell download-val">${formatGB(r.download_gb)}</td>
              <td class="num-cell upload-val">${formatGB(r.upload_gb)}</td>
              <td class="num-cell total-val">${formatGB(r.total_gb)}</td>
              <td>
                <span class="status-badge ${st.class}">
                  ${st.label}
                </span>
              </td>
            </tr>
          `;
        }

        html += `
          <div class="port-detail-card" id="port-card-${p.port}">
            <div class="port-detail-header">
              <div class="port-title-meta">
                <span class="port-number-badge">${p.port}</span>
                <div class="port-info-meta">
                  <div style="font-weight: 700; font-size: 1rem;">پورت TCP/UDP ${p.port}</div>
                  <div class="port-since">آغاز ثبت: ${p.since || '-'}</div>
                </div>
              </div>
              <div style="display: flex; gap: 10px; align-items: center;">
                <span style="font-size: 0.85rem; color: var(--text-secondary);">کل مصرف پورت:</span>
                <span style="font-family: var(--font-mono); font-size: 1.1rem; font-weight: 700; color: var(--accent-cyan);">${formatGB(p.total_gb)} GB</span>
              </div>
            </div>

            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th>دوره زمانی</th>
                    <th>دانلود (GB)</th>
                    <th>آپلود (GB)</th>
                    <th>مجموع (GB)</th>
                    <th>وضعیت داده</th>
                  </tr>
                </thead>
                <tbody>
                  ${rowsHtml}
                </tbody>
              </table>
            </div>

            <div class="chart-section">
              <div class="chart-header">
                <span class="chart-title">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"></path><path d="m19 9-5 5-4-4-3 3"></path></svg>
                  <span>نمودار فعالیت اخیر (دقیقه‌ای)</span>
                </span>
                <div class="chart-legend">
                  <div class="legend-item">
                    <div class="legend-color" style="background: var(--accent-emerald);"></div>
                    <span>دانلود</span>
                  </div>
                  <div class="legend-item">
                    <div class="legend-color" style="background: var(--accent-violet);"></div>
                    <span>آپلود</span>
                  </div>
                </div>
              </div>
              <div class="chart-wrapper" id="chart-port-${p.port}">
                <div class="chart-empty">در حال آماده‌سازی نمودار...</div>
              </div>
            </div>
          </div>
        `;
      }

      container.innerHTML = html;

      // Load charts for rendered ports
      for (const p of filtered) {
        const chartEl = document.getElementById(`chart-port-${p.port}`);
        if (chartEl) {
          loadPortHistory(p.port, chartEl);
        }
      }
    }

    document.getElementById('btn-refresh').addEventListener('click', fetchData);
    document.getElementById('tz-select').addEventListener('change', fetchData);

    // Initial load and periodic refresh (every 10s)
    fetchData();
    setInterval(fetchData, 10000);
  </script>
</body>
</html>
"""


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
    web_parser = sub.add_parser("web", help="Start web dashboard and REST API server")
    web_parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    web_parser.add_argument("--port", type=int, default=9090, help="Listen port (default: 9090)")
    web_parser.add_argument("--timezone", default="Asia/Tehran", help="Default timezone (default: Asia/Tehran)")
    args_list = list(sys.argv[1:] if argv is None else argv)
    index = 2 if args_list[:1] == ["--state-dir"] else 0
    if index < len(args_list) and re.fullmatch(r"[0-9]+", args_list[index]):
        args_list.insert(index, "show")
    if not args_list:
        args_list = ["show"]
    args = parser.parse_args(args_list)
    if hasattr(args, "timezone"):
        report_timezone(args.timezone)
    if args.command == "web":
        report_timezone(args.timezone)
        server = create_web_server(
            state_dir=args.state_dir,
            host=args.host,
            port=args.port,
            default_zone=args.timezone,
        )
        print(f"PortLedger web server listening on http://{args.host}:{args.port} (timezone: {args.timezone})")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
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
