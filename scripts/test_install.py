"""End-to-end tests for scripts/install.sh.

Each test packages a locally built llm-proxy the way the release workflow does,
installs it into a temporary HOME as a background process on ephemeral ports,
and talks to the running admin server. The service-manager paths (launchd and
systemd) are not exercised here; they need a real login session.

Set LLM_PROXY_BIN to choose the binary (default: target/debug/llm-proxy).
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "scripts" / "install.sh"
BINARY = Path(os.environ.get("LLM_PROXY_BIN", ROOT / "target" / "debug" / "llm-proxy"))
UI_DIST = ROOT / "admin-ui" / "dist"
# `curl | sh` runs dash on Debian and Ubuntu; test with it where available.
SHELL = shutil.which("dash") or "/bin/sh"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url, *, method="GET", token=None, body=None):
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@unittest.skipUnless(BINARY.is_file(), f"{BINARY} not built; run cargo build -p proxy")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="llm-proxy-install-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.data = self.home / ".config" / "llm-proxy"
        self.bin = self.home / ".local" / "bin" / "llm-proxy"
        self.port = free_port()
        self.admin_port = free_port()
        self.tarball = self.package()
        self.addCleanup(self.kill_installed)

    def package(self):
        asset = self.tmp / "llm-proxy-test.tar.gz"
        with tarfile.open(asset, "w:gz") as tar:
            tar.add(BINARY, arcname="llm-proxy")
            if UI_DIST.is_dir():
                tar.add(UI_DIST, arcname="admin-ui-dist")
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        Path(f"{asset}.sha256").write_text(f"{digest}  {asset.name}\n")
        return asset

    def install(self, *args, check=True, url=None):
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.home),
            "LLM_PROXY_DOWNLOAD_URL": url or self.tarball.as_uri(),
        }
        result = subprocess.run(
            [SHELL, str(INSTALLER), "--no-service", *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def kill_installed(self):
        pid_file = self.data / "llm-proxy.pid"
        if pid_file.exists():
            pid = int(pid_file.read_text())
            if pid_alive(pid):
                os.kill(pid, 15)

    def admin(self, path, **kwargs):
        return request(f"http://127.0.0.1:{self.admin_port}{path}", **kwargs)

    def token(self):
        line = (self.data / "service.env").read_text().strip()
        return line.removeprefix("LLMPROXY_ADMIN_TOKEN=")

    def fresh_install(self):
        return self.install("--port", str(self.port), "--admin-port", str(self.admin_port))

    def test_install_starts_proxy_with_ui_and_token_gated_writes(self):
        result = self.fresh_install()

        self.assertIn(f"http://127.0.0.1:{self.admin_port}/ui/", result.stdout)
        self.assertIn(self.token(), result.stdout)
        self.assertEqual(self.admin("/ready")[0], 200)
        if UI_DIST.is_dir():
            status, body = self.admin("/ui/")
            self.assertEqual(status, 200)
            self.assertIn("<html", body.lower())
        self.assertEqual(oct((self.data / "service.env").stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct((self.data / "auth-secret").stat().st_mode & 0o777), "0o600")
        # `llm-proxy init` writes an admin token too; the service must use that
        # one, or the file next to the config would hold a token that fails.
        self.assertEqual(oct((self.data / "admin-token").stat().st_mode & 0o777), "0o600")
        self.assertEqual((self.data / "admin-token").read_text(), self.token())

        # The generated token is what makes the UI able to manage anything:
        # without it the admin server refuses every write.
        self.assertEqual(self.admin("/keys", method="POST", body={})[0], 401)
        status, body = self.admin("/keys", method="POST", body={}, token=self.token())
        self.assertNotIn(status, (401, 403), body)

        # The proxy listener uses the requested port, and the starter config's
        # key authentication is on.
        status, _ = request(
            f"http://127.0.0.1:{self.port}/v1/chat/completions",
            method="POST",
            body={"model": "x", "messages": []},
        )
        self.assertEqual(status, 401)

    def test_loopback_admin_is_the_default_and_is_not_warned_about(self):
        result = self.fresh_install()

        self.assertIn(f"admin: 127.0.0.1:{self.admin_port}\n", (self.data / "llmproxy.yaml").read_text())
        self.assertNotIn("plain HTTP", result.stderr)

    def test_admin_address_exposes_ui_and_warns_on_every_run(self):
        result = self.install(
            "--port", str(self.port), "--admin-address", f"0.0.0.0:{self.admin_port}"
        )

        self.assertIn(f"admin: 0.0.0.0:{self.admin_port}\n", (self.data / "llmproxy.yaml").read_text())
        self.assertIn("plain HTTP", result.stderr)
        self.assertNotIn(f"http://127.0.0.1:{self.admin_port}/ui/", result.stdout)
        self.assertEqual(self.admin("/ready")[0], 200)
        # Reachable on an interface other than loopback.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            host = probe.getsockname()[0]
        if host != "0.0.0.0":
            status, _ = request(f"http://{host}:{self.admin_port}/ready")
            self.assertEqual(status, 200)

        rerun = self.install()
        self.assertIn("plain HTTP", rerun.stderr)

    def test_admin_address_rejects_bad_values(self):
        for args in (
            ["--admin-address", "0.0.0.0"],
            ["--admin-address", "0.0.0.0:http"],
            ["--admin-address", "0.0.0.0:1", "--admin-port", "2"],
        ):
            result = self.install(*args, check=False)
            self.assertNotEqual(result.returncode, 0, args)
            self.assertFalse(self.bin.exists(), args)

    def test_rerun_upgrades_in_place_and_keeps_config_and_token(self):
        self.fresh_install()
        config = (self.data / "llmproxy.yaml").read_text()
        token = self.token()
        first_pid = int((self.data / "llm-proxy.pid").read_text())

        result = self.install()

        self.assertIn("Keeping existing", result.stdout)
        self.assertNotIn(token, result.stdout)
        self.assertEqual((self.data / "llmproxy.yaml").read_text(), config)
        self.assertEqual(self.token(), token)
        self.assertFalse(pid_alive(first_pid), "the old process must be replaced")
        self.assertEqual(self.admin("/ready")[0], 200)

    def test_checksum_mismatch_installs_nothing(self):
        Path(f"{self.tarball}.sha256").write_text("0" * 64 + "  x\n")

        result = self.install(check=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse(self.bin.exists())
        self.assertFalse(self.data.exists())

    def test_refuses_to_start_when_admin_port_is_taken(self):
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", self.admin_port))
            busy.listen()
            # A bound but silent port makes the proxy fail to bind; the
            # installer must report that rather than claim success.
            result = self.install(
                "--port", str(self.port), "--admin-port", str(self.admin_port), check=False
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("llm-proxy is running", result.stdout)

    def test_uninstall_stops_proxy_and_keeps_data_unless_purged(self):
        self.fresh_install()
        pid = int((self.data / "llm-proxy.pid").read_text())

        self.install("--uninstall")

        deadline = time.monotonic() + 10
        while pid_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(pid_alive(pid))
        self.assertFalse(self.bin.exists())
        self.assertTrue((self.data / "llmproxy.yaml").exists())

        self.install("--uninstall", "--purge")
        self.assertFalse(self.data.exists())


if __name__ == "__main__":
    unittest.main()
