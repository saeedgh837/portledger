import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "Installer requires a POSIX shell")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.target = self.root / "sbin" / "port-traffic"
        self.target.parent.mkdir()
        self.units = self.root / "units"
        self.units.mkdir()
        self.base = self.root / "package"
        self.base.mkdir()
        shutil.copy(ROOT / "port_traffic.py", self.base / "port_traffic.py")
        shutil.copytree(ROOT / "systemd", self.base / "systemd")
        if (ROOT / "nginx").exists():
            shutil.copytree(ROOT / "nginx", self.base / "nginx")
        script = (ROOT / "install.sh").read_text()
        for source, target in (("/var/lib/port-traffic", str(self.state)),
                               ("/usr/local/sbin/port-traffic", str(self.target)),
                               ("/etc/systemd/system/", str(self.units) + "/")):
            script = script.replace(source, target)
        self.script = self.base / "install.sh"
        self.script.write_text(script)
        for name, body in {
            "id": "printf '0\\n'",
            "date": "printf '20261026T000000Z\\n'",
            "python3": "exit 0",
            "systemctl": "exit 0",
            "systemd-analyze": "exit 0",
            "nft": 'printf "%s\\n" "$SNAPSHOT"; sleep 0.15',
        }.items():
            path = self.bin / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def launch(self, label):
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"], SNAPSHOT=label)
        return subprocess.Popen(["sh", str(self.script)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def finish(self, process):
        stdout, stderr = process.communicate(timeout=20)
        self.assertEqual(process.returncode, 0, stdout + stderr)

    def test_same_timestamp_retries_preserve_distinct_snapshots(self):
        self.target.write_text("original executable\n")
        self.finish(self.launch("first snapshot"))
        self.finish(self.launch("second snapshot"))
        backups = list((self.state / "backups").glob("*/firewall-before.json"))
        self.assertEqual(len(backups), 2)
        self.assertEqual({p.read_text().strip() for p in backups}, {"first snapshot", "second snapshot"})
        self.assertTrue(any((p.parent / "port-traffic.previous").read_text() == "original executable\n"
                            for p in backups))

    def test_installations_wait_for_existing_install_lock(self):
        self.state.mkdir()
        import fcntl
        with (self.state / "install.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            process = self.launch("locked snapshot")
            time.sleep(0.5)
            waiting = process.poll() is None
            installed_while_locked = self.target.exists()
            fcntl.flock(lock, fcntl.LOCK_UN)
        self.finish(process)
        self.assertTrue(waiting, "Installer did not wait for the held installation lock")
        self.assertFalse(installed_while_locked, "Installer overwrote files without owning the lock")
        self.assertTrue(self.target.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
