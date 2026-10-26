"""Must run with: unshare --net -- python3 tests/integration_linux.py"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("port_traffic", ROOT / "port_traffic.py")
pt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pt)
PORT = 47655


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


class KernelIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
            raise RuntimeError("Refusing integration tests in host network namespace")
        run("ip", "link", "set", "lo", "up")

    def setUp(self):
        subprocess.run(["nft", "delete", "table", "inet", "port_traffic"], capture_output=True)
        self.tmp = tempfile.TemporaryDirectory()
        self.meter = pt.Meter(self.tmp.name)
        self.meter.add(str(PORT), "lo")

    def tearDown(self):
        self.tmp.cleanup()
        subprocess.run(["nft", "delete", "table", "inet", "port_traffic"], capture_output=True)

    def report(self):
        value = run(sys.executable, str(ROOT / "port_traffic.py"), "--state-dir", self.tmp.name,
                    "show", str(PORT), "--json")
        return json.loads(value)

    def udp_exchange(self, family, port=PORT):
        address = "127.0.0.1" if family == socket.AF_INET else "::1"
        with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
            server.settimeout(2)
            client.settimeout(2)
            server.bind((address, port))
            client.sendto(b"U" * 100, (address, port))
            received, peer = server.recvfrom(2048)
            self.assertEqual(received, b"U" * 100)
            server.sendto(b"D" * 200, peer)
            self.assertEqual(client.recvfrom(2048)[0], b"D" * 200)

    def test_ipv4_udp_counts_exact_ip_bytes_in_both_directions(self):
        self.udp_exchange(socket.AF_INET)
        report = self.report()
        self.assertEqual((report["upload_bytes"], report["download_bytes"], report["total_bytes"]),
                         (128, 228, 356))
        self.assertEqual(self.report()["total_bytes"], 356)

    def test_ipv6_udp_counts_exact_ip_bytes(self):
        self.udp_exchange(socket.AF_INET6)
        report = self.report()
        self.assertEqual((report["upload_bytes"], report["download_bytes"]), (148, 248))

    def test_other_port_traffic_is_not_charged(self):
        self.udp_exchange(socket.AF_INET, PORT + 1)
        self.assertEqual(self.report()["total_bytes"], 0)

    def test_tcp_counts_handshake_payload_acknowledgements_and_close(self):
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", PORT))
            server.listen()
            with socket.socket() as client:
                client.settimeout(2)
                client.connect(("127.0.0.1", PORT))
                peer, _ = server.accept()
                with peer:
                    peer.settimeout(2)
                    client.sendall(b"U" * 4096)
                    self.assertEqual(len(peer.recv(8192)), 4096)
                    peer.sendall(b"D" * 8192)
                    remaining = 8192
                    while remaining:
                        data = client.recv(16384)
                        self.assertTrue(data)
                        remaining -= len(data)
        report = self.report()
        self.assertGreater(report["upload_bytes"], 4096)
        self.assertGreater(report["download_bytes"], 8192)
        snap = self.meter.snapshot()["counters"]
        self.assertEqual(report["upload_bytes"], snap[f"p{PORT}_rx"])
        self.assertEqual(report["download_bytes"], snap[f"p{PORT}_tx"])

    def test_repeated_add_does_not_reset_balance(self):
        self.udp_exchange(socket.AF_INET)
        self.meter.add(str(PORT), "lo")
        self.assertEqual(self.report()["total_bytes"], 356)

    def test_checkpoint_survives_kernel_table_loss(self):
        self.udp_exchange(socket.AF_INET)
        self.assertEqual(self.report()["total_bytes"], 356)
        run("nft", "delete", "table", "inet", "port_traffic")
        run(sys.executable, str(ROOT / "port_traffic.py"), "--state-dir", self.tmp.name, "restore")
        self.udp_exchange(socket.AF_INET)
        report = self.report()
        self.assertEqual(report["total_bytes"], 712)
        self.assertTrue(report["warnings"])

    def test_new_port_crash_before_kernel_install_retains_pending_intent(self):
        real = self.meter.transaction
        def fail_on_new_port(script):
            if str(PORT + 1) in script:
                raise RuntimeError("simulated process interruption")
            return real(script)
        with patch.object(self.meter, "transaction", side_effect=fail_on_new_port):
            with self.assertRaises(RuntimeError):
                self.meter.add(str(PORT + 1), "lo")
        saved = pt.read_state(self.meter.path)
        self.assertIn(str(PORT + 1), saved["ports"])
        self.meter.sync()
        self.udp_exchange(socket.AF_INET, PORT + 1)
        saved = self.meter.sync()
        self.assertEqual(saved["ports"][str(PORT + 1)]["rx_bytes"], 128)

    def test_foreign_firewall_rules_remain_unchanged(self):
        subprocess.run(["nft", "-f", "-"], input="add table ip unrelated\nadd chain ip unrelated kept\nadd rule ip unrelated kept tcp dport 22 counter\n", text=True, check=True)
        before = json.loads(run("nft", "-j", "list", "table", "ip", "unrelated"))
        self.meter.add(str(PORT + 1), "lo")
        self.meter.sync()
        after = json.loads(run("nft", "-j", "list", "table", "ip", "unrelated"))
        self.assertEqual(before, after)
        run("nft", "delete", "table", "ip", "unrelated")

    def test_source_interface_filter_ignores_wrong_interface(self):
        self.meter.sync()
        run("nft", "delete", "table", "inet", "port_traffic")
        state = pt.read_state(self.meter.path)
        state["interface"] = "eth99"
        pt.save_state(self.meter.path, state)
        self.meter.sync()
        self.udp_exchange(socket.AF_INET)
        self.assertEqual(self.report()["total_bytes"], 0)

    def test_modified_rule_cannot_silently_charge_another_port(self):
        snap = self.meter.snapshot()
        rule = next(r for r in snap["rules"] if r["comment"] == f"port-traffic:{PORT}:rx")
        script = (f'replace rule inet port_traffic incoming handle {rule["handle"]} '
                  f'iifname "lo" meta l4proto {{ tcp, udp }} th dport {PORT + 1} '
                  f'counter name p{PORT}_rx comment "port-traffic:{PORT}:rx"\n')
        subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True)
        with self.assertRaises(ValueError):
            self.meter.sync()

    def test_pending_install_recovery_does_not_double_existing_counters(self):
        real = self.meter.transaction
        def install_then_interrupt(script):
            result = real(script)
            if str(PORT + 1) in script:
                raise RuntimeError("simulated crash after atomic kernel commit")
            return result
        with patch.object(self.meter, "transaction", side_effect=install_then_interrupt):
            with self.assertRaises(RuntimeError):
                self.meter.add(str(PORT + 1), "lo")
        self.udp_exchange(socket.AF_INET, PORT + 1)
        saved = self.meter.sync()
        self.assertEqual(saved["ports"][str(PORT + 1)]["rx_bytes"], 128)
        self.assertEqual(saved["ports"][str(PORT + 1)]["tx_bytes"], 228)
        self.assertEqual(self.report()["total_bytes"], 0)

    def test_concurrent_readers_cannot_double_charge(self):
        self.udp_exchange(socket.AF_INET)
        processes = [subprocess.Popen([sys.executable, str(ROOT / "port_traffic.py"),
                     "--state-dir", self.tmp.name, "sync"], stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE) for _ in range(8)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stderr.decode())
        self.assertEqual(self.report()["total_bytes"], 356)

    def test_replayed_counters_after_boot_are_not_charged_again(self):
        self.udp_exchange(socket.AF_INET)
        for raw_rx, raw_tx in ((1000, 2000), (0, 0)):
            with self.subTest(previous_raw=(raw_rx, raw_tx)):
                saved = self.meter.sync()
                saved["boot_id"] = "previous-boot"
                saved["ports"][str(PORT)].update(rx_bytes=1000, tx_bytes=2000,
                                                 raw_rx=raw_rx, raw_tx=raw_tx)
                pt.save_state(self.meter.path, saved)
                report = self.report()
                self.assertEqual((report["upload_bytes"], report["download_bytes"]), (1000, 2000))
                self.assertTrue(any(e["kind"] == "boot_rebase" for e in report["warnings"]))
                self.udp_exchange(socket.AF_INET)
                report = self.report()
                self.assertEqual((report["upload_bytes"], report["download_bytes"]), (1128, 2228))
                self.assertEqual(self.report()["total_bytes"], 3356)

    def test_interrupted_boot_rebase_cannot_replay_old_counters(self):
        self.udp_exchange(socket.AF_INET)
        saved = self.meter.sync()
        saved["boot_id"] = "previous-boot"
        saved["ports"][str(PORT)].update(rx_bytes=1000, tx_bytes=2000, raw_rx=1000, raw_tx=2000)
        pt.save_state(self.meter.path, saved)
        with patch.object(pt, "save_state", side_effect=OSError("simulated interrupted disk write")):
            with self.assertRaises(OSError):
                self.meter.sync()
        self.assertEqual(pt.read_state(self.meter.path), saved)
        self.assertEqual(self.report()["total_bytes"], 3000)
        self.udp_exchange(socket.AF_INET)
        self.assertEqual(self.report()["total_bytes"], 3356)

    def test_boot_rebase_rejects_changed_rules_without_changing_balance(self):
        saved = pt.read_state(self.meter.path)
        saved["boot_id"] = "previous-boot"
        pt.save_state(self.meter.path, saved)
        snap = self.meter.snapshot()
        rule = next(r for r in snap["rules"] if r["comment"] == f"port-traffic:{PORT}:rx")
        script = (f'replace rule inet port_traffic incoming handle {rule["handle"]} '
                  f'iifname "lo" meta l4proto {{ tcp, udp }} th dport {PORT + 1} '
                  f'counter name p{PORT}_rx comment "port-traffic:{PORT}:rx"\n')
        subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True)
        with self.assertRaises(ValueError):
            self.meter.sync()
        self.assertEqual(pt.read_state(self.meter.path), saved)

    def test_shortcut_cli_and_all_ports_cli(self):
        self.udp_exchange(socket.AF_INET)
        text = run(sys.executable, str(ROOT / "port_traffic.py"), "--state-dir", self.tmp.name, str(PORT))
        self.assertIn("356", text)
        text = run(sys.executable, str(ROOT / "port_traffic.py"), "--state-dir", self.tmp.name, "list", "--json")
        self.assertEqual(json.loads(text)[0]["total_bytes"], 356)


if __name__ == "__main__":
    unittest.main(verbosity=2)
