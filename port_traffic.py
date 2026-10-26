#!/usr/bin/python3
"""Persistent, non-filtering per-port nftables accounting for local listeners."""
from __future__ import annotations

import argparse
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
import uuid

TABLE = "port_traffic"
PREFIX = "port-traffic:v1:"
DEFAULT_DIR = "/var/lib/port-traffic"


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


def apply_sample(state, snapshot, now):
    if snapshot["generation"] != state["generation"]:
        raise ValueError("Kernel table generation does not match saved state; refusing ambiguous accounting")
    result = copy.deepcopy(state)
    for port, entry in result["ports"].items():
        for direction in ("rx", "tx"):
            name = f"p{port}_{direction}"
            if name not in snapshot["counters"]:
                raise ValueError(f"Missing kernel counter {name}; not reporting an incomplete balance")
            current = byte_count(snapshot["counters"][name])
            previous = byte_count(entry[f"raw_{direction}"])
            if current < previous:
                record_event(result, "counter_reset", f"{name}: possible unsaved bytes before external reset", now)
                delta = current
            else:
                delta = current - previous
            entry[f"{direction}_bytes"] += delta
            entry[f"raw_{direction}"] = current
    result["last_sync"] = now
    return result


def new_generation(state, generation, boot_id, reason):
    result = copy.deepcopy(state)
    if result["generation"] is not None:
        record_event(result, "restored", reason + "; totals retained; traffic after last checkpoint may be missing", utcnow())
    result["generation"] = generation
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


def validate_state(state):
    if state.get("version") != 1 or not isinstance(state.get("ports"), dict):
        raise ValueError("Unsupported or corrupt state; restore a checked backup, never delete the balance")
    valid_interface(state["interface"])
    if state["generation"] is not None and not re.fullmatch(r"[a-zA-Z0-9]+", state["generation"]):
        raise ValueError("Invalid saved generation")
    if not isinstance(state["events"], list):
        raise ValueError("Invalid saved events")
    for port, entry in state["ports"].items():
        if valid_port(port) != port:
            raise ValueError("Noncanonical saved port")
        for key in ("rx_bytes", "tx_bytes", "raw_rx", "raw_tx"):
            byte_count(entry[key])
        if not isinstance(entry["since"], str):
            raise ValueError("Invalid start timestamp")
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


def make_report(state, port):
    entry = state["ports"][port]
    rx, tx = entry["rx_bytes"], entry["tx_bytes"]
    return {"port": int(port), "interface": state["interface"],
            "since": entry["since"], "updated": state["last_sync"],
            "upload_bytes": rx, "download_bytes": tx, "total_bytes": rx + tx,
            "upload_gb": f"{Decimal(rx) / Decimal(1_000_000_000):.6f}",
            "download_gb": f"{Decimal(tx) / Decimal(1_000_000_000):.6f}",
            "total_gb": f"{Decimal(rx + tx) / Decimal(1_000_000_000):.6f}",
            "warnings": state["events"]}


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
            record_event(state, "boot_rebase",
                         "boot changed with existing counters; restored values were not charged; "
                         "traffic before this baseline may be missing", utcnow())
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
        state = apply_sample(state, snap, utcnow())
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
            state = {"version": 1, "generation": None, "boot_id": None,
                     "interface": interface, "ports": {}, "last_sync": None, "events": []}
            save_state(self.path, state)
            state, _ = self.ensure(state)
        if port in state["ports"]:
            return state
        state["ports"][port] = {"since": utcnow(), "rx_bytes": 0, "tx_bytes": 0,
                                "raw_rx": 0, "raw_tx": 0, "pending": True}
        # Commit intent first; ensure() can finish an interrupted kernel transaction idempotently.
        save_state(self.path, state)
        return self.sync()


def print_reports(state, port, as_json):
    if state is None or not state["ports"]:
        raise ValueError("No tracked ports. Start with: port-traffic add PORT")
    if port and port not in state["ports"]:
        raise ValueError(f"Port {port} is not tracked. Run: port-traffic add {port}")
    ports = [port] if port else sorted(state["ports"], key=int)
    reports = [make_report(state, p) for p in ports]
    if as_json:
        print(json.dumps(reports[0] if port else reports, indent=2))
        return
    for report in reports:
        print(f"Port {report['port']} | TCP + UDP | IPv4 + IPv6 | {report['interface']}")
        print(f"Since (UTC): {report['since']}")
        print(f"Upload   (client -> server): {report['upload_gb']:>16} GB")
        print(f"Download (server -> client): {report['download_gb']:>16} GB")
        print(f"TOTAL                     : {report['total_gb']:>16} GB")
        print(f"Exact total bytes: {report['total_bytes']}")
        print("1 GB = 1,000,000,000 bytes; IP-stack traffic, including headers and retransmissions.")
        if report["warnings"]:
            print(f"WARNING: {len(report['warnings'])} accounting event(s); completeness is not guaranteed.")
            for event in report["warnings"][-3:]:
                print(f"  {event['time']}: {event['kind']}: {event['detail']}")
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog="Shortcut: port-traffic 40199")
    parser.add_argument("--state-dir", default=DEFAULT_DIR)
    sub = parser.add_subparsers(dest="command")
    add = sub.add_parser("add", help="Start tracking a port; repeat calls never reset its balance")
    add.add_argument("port")
    add.add_argument("--interface", type=valid_interface)
    for command in ("show", "list"):
        show = sub.add_parser(command, help="Read and save live cumulative usage")
        show.add_argument("port", nargs="?")
        show.add_argument("--json", action="store_true")
    for command in ("sync", "restore", "doctor"):
        sub.add_parser(command)
    args_list = list(sys.argv[1:] if argv is None else argv)
    index = 2 if args_list[:1] == ["--state-dir"] else 0
    if index < len(args_list) and re.fullmatch(r"[0-9]+", args_list[index]):
        args_list.insert(index, "show")
    if not args_list:
        args_list = ["show"]
    args = parser.parse_args(args_list)
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
            print_reports(state, valid_port(args.port), False)
        elif args.command in ("show", "list", None):
            port = valid_port(args.port) if getattr(args, "port", None) else None
            print_reports(meter.sync(), port, getattr(args, "json", False))
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
