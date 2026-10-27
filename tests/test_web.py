import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

SOURCE = Path(__file__).resolve().parents[1] / "port_traffic.py"
SPEC = importlib.util.spec_from_file_location("port_traffic", SOURCE)
pt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pt)


def sample_state():
    return {
        "version": 2,
        "generation": "gen123",
        "interface": "eth0",
        "boot_id": "boot-uuid-001",
        "events": [],
        "last_sync": "2026-10-27T10:00:00+00:00",
        "last_monotonic_ns": 1000000000,
        "history_pruning_suspended": False,
        "ports": {
            "40199": {
                "since": "2026-10-01T00:00:00+00:00",
                "rx_bytes": 10_000_000_000,  # 10 GB upload
                "tx_bytes": 25_000_000_000,  # 25 GB download
                "raw_rx": 500,
                "raw_tx": 1000,
                "history": {
                    "since": "2026-10-01T00:00:00+00:00",
                    "retained_since": 1790812800,
                    "buckets": [
                        [1793085540, 500_000, 1_500_000],
                        [1793085600, 1_000_000, 2_000_000],  # 2026-10-27T10:00:00Z
                    ],
                    "gaps": [],
                },
            },
            "8443": {
                "since": "2026-10-15T00:00:00+00:00",
                "rx_bytes": 1_000_000_000,
                "tx_bytes": 2_000_000_000,
                "raw_rx": 100,
                "raw_tx": 200,
                "history": {
                    "since": "2026-10-15T00:00:00+00:00",
                    "retained_since": 1790812800,
                    "buckets": [],
                    "gaps": [],
                },
            },
        },
    }


class WebServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name)
        self.state_path = self.state_dir / "state.json"
        pt.save_state(self.state_path, sample_state())

        # Start test web server on ephemeral port (0)
        self.server = pt.create_web_server(
            state_dir=str(self.state_dir),
            host="127.0.0.1",
            port=0,
            default_zone="Asia/Tehran",
        )
        self.server_port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.server_port}"

        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def fetch(self, path):
        req = urllib.request.Request(f"{self.base_url}{path}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read()
            return resp.status, resp.headers, data

    def test_health_endpoint(self):
        status, headers, data = self.fetch("/api/health")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        payload = json.loads(data.decode("utf-8"))
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["ports_count"], 2)
        self.assertEqual(payload["interface"], "eth0")
        self.assertIn("last_sync", payload)

    def test_overview_endpoint(self):
        status, headers, data = self.fetch("/api/overview")
        self.assertEqual(status, 200)
        payload = json.loads(data.decode("utf-8"))
        self.assertEqual(payload["interface"], "eth0")
        self.assertEqual(payload["ports"], ["8443", "40199"])
        # Total bytes across both ports: (10G + 25G) + (1G + 2G) = 38,000,000,000
        self.assertEqual(payload["total_bytes"], 38_000_000_000)
        self.assertEqual(payload["total_gb"], "38.000000")
        self.assertEqual(payload["download_bytes"], 27_000_000_000)
        self.assertEqual(payload["download_gb"], "27.000000")
        self.assertEqual(payload["upload_bytes"], 11_000_000_000)
        self.assertEqual(payload["upload_gb"], "11.000000")

    def test_ports_list_endpoint(self):
        status, headers, data = self.fetch("/api/ports")
        self.assertEqual(status, 200)
        payload = json.loads(data.decode("utf-8"))
        self.assertIsInstance(payload, list)
        self.assertEqual(len(payload), 2)
        port_numbers = [p["port"] for p in payload]
        self.assertEqual(port_numbers, [8443, 40199])
        # Ensure 5 accounting periods are present on each port
        p40199 = next(p for p in payload if p["port"] == 40199)
        self.assertEqual(len(p40199["periods"]), 5)
        period_keys = [r["key"] for r in p40199["periods"]]
        self.assertEqual(period_keys, ["today", "last_24_hours", "last_7_days", "last_30_days", "all_time"])

    def test_single_port_endpoint(self):
        status, headers, data = self.fetch("/api/ports/40199")
        self.assertEqual(status, 200)
        payload = json.loads(data.decode("utf-8"))
        self.assertEqual(payload["port"], 40199)
        self.assertEqual(payload["total_bytes"], 35_000_000_000)
        self.assertEqual(payload["total_gb"], "35.000000")
        self.assertEqual(payload["download_bytes"], 25_000_000_000)
        self.assertEqual(payload["download_gb"], "25.000000")
        self.assertEqual(payload["upload_bytes"], 10_000_000_000)
        self.assertEqual(payload["upload_gb"], "10.000000")

    def test_single_port_custom_timezone(self):
        status, headers, data = self.fetch("/api/ports/40199?zone=UTC")
        self.assertEqual(status, 200)
        payload = json.loads(data.decode("utf-8"))
        self.assertEqual(payload["timezone"], "UTC")

    def test_single_port_not_found(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.fetch("/api/ports/7777")
        self.assertEqual(ctx.exception.code, 404)
        err_data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("error", err_data)

    def test_invalid_port_number(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.fetch("/api/ports/999999")
        self.assertEqual(ctx.exception.code, 400)
        err_data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("error", err_data)

    def test_port_history_endpoint(self):
        status, headers, data = self.fetch("/api/ports/40199/history")
        self.assertEqual(status, 200)
        payload = json.loads(data.decode("utf-8"))
        self.assertEqual(payload["port"], "40199")
        self.assertIsInstance(payload["buckets"], list)
        self.assertEqual(len(payload["buckets"]), 2)
        first = payload["buckets"][0]
        self.assertIn("timestamp", first)
        self.assertIn("epoch", first)
        self.assertIn("upload_bytes", first)
        self.assertIn("download_bytes", first)
        self.assertIn("total_bytes", first)

    def test_dashboard_html_root(self):
        status, headers, data = self.fetch("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "SAMEORIGIN")
        html = data.decode("utf-8")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("PortLedger", html)
        self.assertIn("viewport", html)
        # Verify RTL and Persian typography references
        self.assertIn('dir="rtl"', html)
        self.assertIn("Vazirmatn", html)

    def test_head_requests(self):
        req = urllib.request.Request(f"{self.base_url}/", method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "text/html; charset=utf-8")
            self.assertEqual(resp.read(), b"")

        req = urllib.request.Request(f"{self.base_url}/api/health", method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "application/json; charset=utf-8")
            self.assertEqual(resp.read(), b"")

    def test_404_not_found(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.fetch("/api/unknown_route")
        self.assertEqual(ctx.exception.code, 404)
        err_data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("error", err_data)

    def test_missing_state_file_health(self):
        # Create server with empty dir (no state.json)
        with tempfile.TemporaryDirectory() as empty_dir:
            empty_server = pt.create_web_server(state_dir=empty_dir, host="127.0.0.1", port=0)
            e_port = empty_server.server_address[1]
            t = threading.Thread(target=empty_server.serve_forever, daemon=True)
            t.start()
            try:
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    req = urllib.request.Request(f"http://127.0.0.1:{e_port}/api/health")
                    urllib.request.urlopen(req, timeout=5)
                self.assertEqual(ctx.exception.code, 503)
            finally:
                empty_server.shutdown()
                empty_server.server_close()

    def test_web_cli_command(self):
        from unittest.mock import MagicMock, patch
        mock_server = MagicMock()
        with patch.object(pt, "create_web_server", return_value=mock_server) as mock_create:
            ret = pt.main(["--state-dir", "/tmp/test-state", "web", "--host", "127.0.0.2", "--port", "9999", "--timezone", "Asia/Tehran"])
            self.assertEqual(ret, 0)
            mock_create.assert_called_once_with(
                state_dir="/tmp/test-state",
                host="127.0.0.2",
                port=9999,
                default_zone="Asia/Tehran",
            )
            mock_server.serve_forever.assert_called_once()
            mock_server.server_close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
