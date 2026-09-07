"""Exercise replacement consent through the real Make target and a PTY."""

import array
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import pty
import pwd
import select
import shutil
import subprocess
import sys
import tempfile
import termios
import time
import unittest


class InstallConfirmation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository = Path(__file__).resolve().parent.parent
        cls.workspace = tempfile.TemporaryDirectory(prefix="wirepup-confirmation-")
        cls.root = Path(cls.workspace.name)
        cls.source = cls.root / "source"
        cls.previous = cls.root / "previous"
        for binary, version in [(cls.source, "consent-new"), (cls.previous, "consent-old")]:
            subprocess.run(
                ["make", "build", f"BIN={binary}", f"VERSION={version}"],
                cwd=cls.repository, check=True, capture_output=True,
            )

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.prefix = self.root / self.id().rsplit(".", 1)[-1]
        self.destination = self.prefix / "bin" / "wirepup"
        self.destination.parent.mkdir(parents=True)
        shutil.copy2(self.previous, self.destination)
        self.command = [
            "make", "install", f"BIN={self.source}", "VERSION=consent-new",
            f"INSTALL_LOCATION={self.prefix}", "INSTALL_FORCE=0",
        ]

    def terminal(self, answer):
        master, slave = pty.openpty()
        process = subprocess.Popen(
            self.command, cwd=self.repository, stdin=slave, stdout=slave, stderr=slave,
        )
        os.close(slave)
        output = b""
        answers = [answer] if isinstance(answer, bytes) else answer
        sent = 0
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline:
                if not select.select([master], [], [], 0.1)[0]:
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output += chunk
                if sent < len(answers) and output.count(b"Replace this file? [y/N]") > sent:
                    os.write(master, answers[sent])
                    sent += 1
            else:
                self.fail("installation did not finish within 30 seconds")
            self.assertEqual(sent, len(answers), output.decode(errors="replace"))
            return process.wait(timeout=5), output
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)

    def test_decline_enter_and_eof_preserve_existing(self):
        for answer in [b"n\n", b"\n", b"\x04"]:
            with self.subTest(answer=answer):
                status, output = self.terminal(answer)
                self.assertNotEqual(status, 0, output)
                self.assertEqual(self.destination.read_bytes(), self.previous.read_bytes())

    def test_yes_replaces_existing(self):
        status, output = self.terminal(b"y\n")
        self.assertEqual(status, 0, output)
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        self.assertNotEqual(self.destination.read_bytes(), self.previous.read_bytes())

    def test_declining_completion_preserves_both_files(self):
        completion = self.prefix / "share" / "bash-completion" / "completions" / "wirepup"
        completion.parent.mkdir(parents=True)
        source = self.repository / "completions" / "wirepup.bash"
        shutil.copy2(source, completion)
        status, output = self.terminal([b"y\n", b"n\n"])
        self.assertNotEqual(status, 0, output)
        self.assertEqual(self.destination.read_bytes(), self.previous.read_bytes())
        self.assertEqual(completion.read_bytes(), source.read_bytes())

    def test_build_output_cannot_be_completion_destination(self):
        completion = self.prefix / "share" / "bash-completion" / "completions" / "wirepup"
        completion.parent.mkdir(parents=True)
        source = self.repository / "completions" / "wirepup.bash"
        shutil.copy2(source, completion)
        result = subprocess.run(
            self.command + [f"BIN={completion}", "INSTALL_FORCE=1"],
            cwd=self.repository, stdin=subprocess.DEVNULL, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(b"refer to the same file", result.stderr)
        self.assertEqual(self.destination.read_bytes(), self.previous.read_bytes())
        self.assertEqual(completion.read_bytes(), source.read_bytes())

    def test_unregistered_completion_preserves_both_files(self):
        completion = self.prefix / "share" / "bash-completion" / "completions" / "wirepup"
        completion.parent.mkdir(parents=True)
        source = self.repository / "completions" / "wirepup.bash"
        shutil.copy2(source, completion)
        fixture = self.prefix / "invalid-source"
        (fixture / "completions").mkdir(parents=True)
        for contents in ["true\n", "complete -F _wirepup wirepup\n",
                         "function _wirepup { :; }\ncomplete -F _missing wirepup\n"]:
            with self.subTest(contents=contents):
                (fixture / "completions" / "wirepup.bash").write_text(contents, encoding="ascii")
                result = subprocess.run(
                    ["bash", "tools/install-wirepup.bash", "apply", str(self.source),
                     str(self.destination), str(fixture)], cwd=self.repository,
                    env=dict(os.environ, INSTALL_FORCE="1"), stdin=subprocess.DEVNULL, capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(b"does not register wirepup", result.stderr)
                self.assertEqual(self.destination.read_bytes(), self.previous.read_bytes())
                self.assertEqual(completion.read_bytes(), source.read_bytes())

    def test_installed_completion_requires_its_own_handler(self):
        completion = self.prefix / "share" / "bash-completion" / "completions" / "wirepup"
        completion.parent.mkdir(parents=True)
        contents = "complete -F _wirepup wirepup\n"
        completion.write_text(contents, encoding="ascii")
        env = dict(os.environ, PATH=f"{self.destination.parent}:{os.environ['PATH']}")
        env["BASH_FUNC__wirepup%%"] = "() { :; }"
        result = subprocess.run(
            ["make", "install.check", f"INSTALL_LOCATION={self.prefix}"], cwd=self.repository,
            env=env, stdin=subprocess.DEVNULL, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(b"defined function", result.stderr)
        self.assertEqual(self.destination.read_bytes(), self.previous.read_bytes())
        self.assertEqual(completion.read_text(encoding="ascii"), contents)

    def test_noninteractive_requires_explicit_approval(self):
        result = subprocess.run(self.command, cwd=self.repository, stdin=subprocess.DEVNULL, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"INSTALL_FORCE=1", result.stderr)
        self.assertEqual(self.destination.read_bytes(), self.previous.read_bytes())
        result = subprocess.run(
            self.command + ["INSTALL_FORCE=1"], cwd=self.repository,
            stdin=subprocess.DEVNULL, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())

    def test_destination_appearing_after_consent_check_is_preserved(self):
        self.destination.unlink()
        command = ["bash", "tools/install-wirepup.bash", "apply", str(self.source),
                   str(self.destination), str(self.repository)]
        baseline = subprocess.run(command, cwd=self.repository, check=True, capture_output=True)
        boundary = baseline.stdout.index(b"Installing binary:")
        self.destination.unlink()
        (self.prefix / "share" / "bash-completion" / "completions" / "wirepup").unlink()
        read_fd, write_fd = os.pipe()
        capacity = fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
        self.assertLess(boundary, capacity)
        padding = b"x" * (capacity - boundary)
        os.write(write_fd, padding)
        process = subprocess.Popen(command, cwd=self.repository, stdout=write_fd, stderr=subprocess.PIPE)
        os.close(write_fd)
        try:
            # Backpressure pauses real stdout after consent, before the copy.
            # No command, function, or filesystem operation is replaced.
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                available = array.array("i", [0])
                fcntl.ioctl(read_fd, termios.FIONREAD, available, True)
                if available[0] == capacity:
                    break
                self.assertIsNone(process.poll())
                time.sleep(0.01)
            else:
                self.fail("stdout did not reach the installation boundary")
            shutil.copy2(self.previous, self.destination)
            with os.fdopen(read_fd, "rb") as stream:
                read_fd = -1
                output = stream.read()
            _, errors = process.communicate(timeout=5)
            self.assertTrue(output.startswith(padding + baseline.stdout[:boundary]))
            self.assertNotEqual(process.returncode, 0, errors)
            self.assertIn(b"destination appeared", errors)
            self.assertEqual(self.destination.read_bytes(), self.previous.read_bytes())
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()
            if read_fd >= 0:
                os.close(read_fd)


def system_race(prefix, completion=False):
    repository = Path(__file__).resolve().parent.parent
    destination = Path(prefix) / "race" / "bin" / "wirepup"
    source = repository / "bin" / "wirepup"
    previous = repository / "bin" / "wirepup.previous"
    helper_args = []
    if completion:
        destination = Path(prefix) / "race" / "share" / "bash-completion" / "completions" / "wirepup"
        source = previous = repository / "completions" / "wirepup.bash"
        helper_args = ["--completion"]
    subprocess.run(["sudo", "-n", "mkdir", "-p", str(destination.parent)], check=True)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    process = subprocess.Popen(
        ["sudo", "-n", "/bin/bash", "-p", "tools/install-system-wirepup.bash", *helper_args,
         str(destination), digest, "0"], cwd=repository,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while not list(destination.parent.glob(".wirepup.*")):
            if process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError("protected copy did not reach its input stage")
            time.sleep(0.01)
        subprocess.run(["sudo", "-n", "install", "-m", "0755", str(previous), str(destination)], check=True)
        inode = destination.stat().st_ino
        _, errors = process.communicate(source.read_bytes(), timeout=10)
        assert process.returncode != 0, "unapproved replacement succeeded"
        assert b"destination appeared" in errors, errors
        assert destination.read_bytes() == previous.read_bytes(), "existing file changed"
        assert destination.stat().st_ino == inode, "existing file was replaced"
        print(f"PASS: protected {'completion' if completion else 'binary'} appearing during copy was preserved")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


def system_noexec(prefix, username):
    repository = Path(__file__).resolve().parent.parent
    source = repository / "bin" / "wirepup"
    previous = repository / "bin" / "wirepup.previous"
    base = Path(prefix)
    user = pwd.getpwnam(username)
    assert os.geteuid() == 0 and user.pw_uid != 0
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    mountpoint = base / "noexec"
    mountpoint.mkdir()
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=32m,noexec,mode=0755",
                    "tmpfs", str(mountpoint)], check=True)
    try:
        destination = mountpoint / "bin" / "wirepup"
        destination.parent.mkdir()
        shutil.copy2(previous, destination)
        command = ["runuser", "-u", username, "--", "env", "INSTALL_FORCE=1",
                   "bash", "tools/install-wirepup.bash", "apply", str(source)]
        result = subprocess.run(command + [str(destination), str(repository)],
                                cwd=repository, capture_output=True)
        assert result.returncode != 0, "installation on noexec unexpectedly succeeded"
        assert b"noexec" in result.stderr, result.stderr
        assert destination.read_bytes() == previous.read_bytes(), "old executable was replaced"
        assert not list(destination.parent.glob(".wirepup.*")), "staged copy was not removed"
        print("PASS: noexec destination refused before replacement; old bytes preserved")

        temporary = mountpoint / "usertmp"
        temporary.mkdir()
        os.chown(temporary, user.pw_uid, user.pw_gid)
        destination = base / "tmpdir-test" / "bin" / "wirepup"
        destination.parent.mkdir(parents=True)
        shutil.copy2(previous, destination)
        result = subprocess.run(
            ["runuser", "-u", username, "--", "env", "INSTALL_FORCE=1", f"TMPDIR={temporary}",
             "bash", "tools/install-wirepup.bash", "apply", str(source), str(destination), str(repository)],
            cwd=repository, capture_output=True,
        )
        assert result.returncode == 0, result.stderr
        assert destination.read_bytes() == source.read_bytes(), "new executable was not installed"
        assert not list(source.parent.glob(".wirepup-source.*")), "source snapshot was not removed"
        print("PASS: noexec TMPDIR permits verified replacement on an executable destination")
    finally:
        subprocess.run(["umount", str(mountpoint)], check=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--system":
        system_race(sys.argv[2])
        system_race(sys.argv[2], completion=True)
    elif len(sys.argv) == 4 and sys.argv[1] == "--noexec":
        system_noexec(sys.argv[2], sys.argv[3])
    else:
        unittest.main()
