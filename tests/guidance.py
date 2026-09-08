"""Exercise the shipped CLI through real terminals, pipes and capture files."""

import errno
import hashlib
import os
from pathlib import Path
import pty
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import time
import unittest

REPOSITORY = Path(__file__).resolve().parent.parent
BINARY = REPOSITORY / "bin" / "wirepup"


class Session:
    """One real process with terminal input/output; no internal substitutions."""

    def __init__(self, argv, cwd=None, redirected_stderr=False, retained_input=False):
        self.master, slave = pty.openpty()
        self.retained_input = os.dup(slave) if retained_input else None
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        self.errors = tempfile.TemporaryFile() if redirected_stderr else None
        self.process = subprocess.Popen(
            list(map(str, argv)), stdin=slave, stdout=slave,
            stderr=self.errors if self.errors is not None else slave,
            cwd=cwd, start_new_session=True,
        )
        os.close(slave)
        self.output, self.cursor, self.operation_cursor = "", 0, 0

    def pump(self, wait=0.1):
        if select.select([self.master], [], [], wait)[0]:
            try:
                data = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                return
            self.output += data.decode(errors="replace").replace("\r\n", "\n")

    def expect(self, pattern, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = re.search(pattern, self.output[self.cursor:], re.S | re.M)
            if found:
                self.cursor += found.end()
                return found
            self.pump()
        raise AssertionError(f"Missing {pattern!r}; exit={self.process.poll()}\n{self.output[-12000:]}")

    def send(self, data):
        while data:
            written = os.write(self.master, data)
            if written <= 0:
                raise AssertionError("Terminal input write made no progress")
            data = data[written:]

    def line(self, value):
        self.send((value + "\n").encode())

    def menu(self, title, item):
        block = self.expect(r"\n" + re.escape(title) + r"\n.*?Choice: ").group()
        found = re.search(r"^\s+(\d+)\s+" + re.escape(item) + r"$", block, re.M)
        if not found:
            raise AssertionError(f"No {item!r} in {block!r}")
        self.line(found[1])

    def answer(self, label, value):
        self.expect(re.escape(label) + r".*?\): ")
        self.line(value)

    def operation(self, timeout=15):
        previous = self.cursor
        self.cursor = self.operation_cursor
        found = self.expect(r"\nCommand: ([^\n]+)\n(.*?)Operation finished \(exit (\d+)\)\.\n", timeout)
        self.operation_cursor = self.cursor
        self.cursor = max(previous, self.cursor)
        self.command_text = found[1]
        return shlex.split(found[1]), found[2], int(found[3])

    def wait(self, timeout=8):
        deadline = time.monotonic() + timeout
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump()
        if self.process.poll() is None:
            raise AssertionError(f"Process did not exit\n{self.output[-12000:]}")
        self.pump(0)
        return self.process.returncode

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.wait()
            except AssertionError:
                self.process.kill()
                self.process.wait()
        os.close(self.master)
        if self.retained_input is not None:
            os.close(self.retained_input)
        if self.errors is not None:
            self.errors.close()


class Guidance(unittest.TestCase):
    def session(self, *args, **kwargs):
        session = Session([BINARY, *args], **kwargs)
        self.addCleanup(session.close)
        return session

    def equivalent(self, session):
        argv, output, code = session.operation()
        direct = subprocess.run(["bash", "-c", session.command_text], cwd=REPOSITORY, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=10)
        self.assertEqual(direct.returncode, code, direct.stdout)
        self.assertEqual(direct.stdout, output)
        return argv, output, code

    def finish(self, session, code=0):
        session.menu("Next action", "Finish")
        self.assertEqual(session.wait(), code)

    def file_source(self, session, purpose, path):
        session.menu("Purpose", purpose)
        if purpose != "Analyze a capture file":
            session.menu("Source", "Capture file")
        session.answer("Capture file", str(path))

    def test_dispatch_stream_matrix(self):
        for terminal_in, terminal_out in [(False, False), (True, False), (False, True)]:
            with self.subTest(stdin=terminal_in, stdout=terminal_out):
                master, slave = pty.openpty()
                with tempfile.TemporaryFile() as out:
                    process = subprocess.Popen([BINARY], stdin=slave if terminal_in else subprocess.DEVNULL,
                                               stdout=slave if terminal_out else out, stderr=out)
                    os.close(slave)
                    try:
                        self.assertEqual(process.wait(timeout=3), 2)
                        out.seek(0)
                        self.assertIn(b"usage:", out.read())
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
                        os.close(master)
        for descriptor in [0, 1]:
            with self.subTest(closed=descriptor):
                # Close the actual inherited descriptor just before exec.
                process = subprocess.run([BINARY], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         preexec_fn=lambda: os.close(descriptor), timeout=3)
                self.assertEqual(process.returncode, 2)
                self.assertIn(b"usage:", process.stderr)
        session = self.session(redirected_stderr=True)
        session.expect(r"Purpose\n.*?Choice: ")
        session.line("q")
        self.assertEqual(session.wait(), 0)
        session.errors.seek(0)
        self.assertEqual(session.errors.read(), b"")
        for args, code in [(["--help"], 0), (["unknown"], 2), (["read"], 2)]:
            session = self.session(*args)
            self.assertEqual(session.wait(), code)
            self.assertNotIn("WirePup guide", session.output)

    def test_three_workflows_and_direct_equivalence(self):
        session = self.session(cwd=REPOSITORY)
        self.file_source(session, "Find devices", "testdata/pcap/same-l2-different-subnet.pcap")
        self.equivalent(session)
        session.menu("Next action", "Diagnose an observed IPv4 address")
        session.menu("Observed IPv4 address", "192.168.1.100")
        session.answer("Original capture-host prefixes", "")
        _, result, _ = self.equivalent(session)
        self.assertIn("local", result)
        self.assertIn("Original prefixes are unknown", session.output)
        self.assertNotIn("Connect temporarily", session.output)
        self.finish(session)

        cases = [
            ("tests/vm/pcap/epics-reads.pcap", "WP:VALUE", 0, "answered"),
            ("testdata/pcap/ca-search-no-response.pcap", "MISSING:PV", 0, "no response"),
            ("testdata/pcap/ca-search-response.pcap", "NOPE:PV", 5, "nothing"),
            ("testdata/pcap/ca-duplicate-servers.pcap", "DUP:PV", 0, "servers"),
            ("testdata/pcap/arp-autoip-selection.pcap", "", 0, "no CA or PVA"),
        ]
        for capture, pv, code, text in cases:
            with self.subTest(capture=capture, pv=pv):
                session = self.session(cwd=REPOSITORY)
                self.file_source(session, "Diagnose EPICS connectivity", capture)
                session.answer("PV name", pv)
                _, result, actual = self.equivalent(session)
                self.assertEqual(actual, code)
                self.assertIn(text, result)
                self.assertNotIn("Send an explicit PV search", session.output)
                self.finish(session, code)

        for view in ["Events", "Devices", "General diagnosis", "EPICS diagnosis"]:
            with self.subTest(view=view):
                session = self.session(cwd=REPOSITORY)
                self.file_source(session, "Analyze a capture file", "testdata/pcap/arp-autoip-selection.pcap")
                session.menu("Capture view", view)
                if view == "General diagnosis":
                    session.answer("Original capture-host prefixes", "10.20.30.51/24")
                self.equivalent(session)
                self.finish(session)

    def test_literal_values_and_navigation(self):
        with tempfile.TemporaryDirectory(prefix="wirepup-guide-") as directory:
            root = Path(directory)
            source = REPOSITORY / "testdata/pcap/ca-search-response.pcap"
            for name in ["b", "q", "-capture.pcap", "a space ' $HOME $(touch BAD).pcap"]:
                shutil.copyfile(source, root / name)
                session = self.session(cwd=root)
                self.file_source(session, "Analyze a capture file", name)
                session.menu("Capture view", "Events")
                argv, output, code = session.operation()
                direct = subprocess.run(["bash", "-c", session.command_text], cwd=root, text=True, capture_output=True, timeout=3)
                self.assertEqual((direct.stdout, direct.returncode), (output, code))
                self.assertEqual(argv[2], "./" + name if name.startswith("-") else name)
                self.finish(session)
            self.assertFalse((root / "BAD").exists())
            session = self.session(cwd=REPOSITORY)
            self.file_source(session, "Diagnose EPICS connectivity", str(source))
            session.answer("PV name", "//quit")
            argv, _, code = self.equivalent(session)
            self.assertEqual(argv[3], "/quit")
            self.finish(session, code)

        session = self.session(cwd=REPOSITORY)
        session.expect(r"Purpose\n.*?Choice: ")
        session.line("99")
        session.expect("Choose a listed number")
        session.menu("Purpose", "Analyze a capture file")
        session.answer("Capture file", "a,b.pcap")
        session.expect("splits commas")
        session.answer("Capture file", "does-not-exist")
        session.expect("Cannot read a regular capture")
        session.answer("Capture file", "/back")
        session.expect(r"Purpose\n.*?Choice: ")
        session.line("q")
        self.assertEqual(session.wait(), 0)

    def test_cancellation_and_partial_confirmation(self):
        for args, prompt in [([], r"Choice: "), (["probe", "-i", "lo", "--arp", "192.0.2.1/32"], r"Proceed\? \[y/N\] ")]:
            for cancellation in [signal.SIGINT, signal.SIGTERM, "eof", "partial-eof"]:
                with self.subTest(args=args, cancellation=cancellation):
                    session = self.session(*args)
                    session.expect(prompt)
                    if isinstance(cancellation, int):
                        session.process.send_signal(cancellation)
                    else:
                        session.send(b"y\x04\x04" if cancellation == "partial-eof" else b"\x04")
                    self.assertEqual(session.wait(timeout=2), 1)
                    self.assertNotIn("sent 1 ARP", session.output)
        session = self.session(cwd=REPOSITORY)
        session.menu("Purpose", "Analyze a capture file")
        session.expect(r"Capture file .*?\): ")
        session.send(b"testdata/pcap/arp-autoip-selection.pcap")
        session.process.send_signal(signal.SIGINT)
        self.assertEqual(session.wait(timeout=2), 1)
        self.assertNotIn("Command:", session.output)

    def test_typeahead_does_not_answer_a_new_prompt(self):
        long_line = "./" * 1400 + "testdata/pcap/ca-search-response.pcap\n"
        for pending in ["y\n", "xy\n", "unfinished", long_line]:
            with self.subTest(pending=pending):
                session = self.session(cwd=REPOSITORY)
                session.expect(r"Purpose\n.*?Choice: ")
                session.send(("3\n" + pending).encode())
                session.expect(r"Capture file .*?\): ")
                # A fresh line must be read intact, without a queued prefix
                # or an extra prompt caused by the previous answer's tail.
                session.line("testdata/pcap/arp-autoip-selection.pcap")
                session.menu("Capture view", "Devices")
                self.equivalent(session)
                self.assertNotIn("Cannot read a regular capture", session.output)
                self.finish(session)

    def test_overlong_input_is_refused_before_dispatch(self):
        for field, payload in [
            ("menu", b"3" + b" " * 252 + b"x\n"),
            ("menu", b"3" + b" " * 5000 + b"invalid\n"),
            ("file", b"a" * 4100 + b"\n"),
            ("pv", b"A" * 254 + b"\n"),
            ("pv", b"A" * 4100 + b"\n"),
            ("pv", ("A" + "\u03a9" * 127 + "\n").encode()),
        ]:
            with self.subTest(field=field, length=len(payload)):
                session = self.session(cwd=REPOSITORY)
                attrs = termios.tcgetattr(session.master)
                self.assertTrue(attrs[3] & termios.ICANON)
                if field == "menu":
                    session.expect(r"Choice: ")
                elif field == "file":
                    session.menu("Purpose", "Analyze a capture file")
                    session.expect(r"Capture file .*?\): ")
                else:
                    self.file_source(session, "Diagnose EPICS connectivity", "testdata/pcap/ca-search-response.pcap")
                    session.expect(r"PV name .*?\): ")
                session.send(payload)
                self.assertEqual(session.wait(timeout=2), 1)
                self.assertIn("input exceeds 253 bytes", session.output)
                self.assertNotIn("Command:", session.output)
                self.assertEqual(termios.tcgetattr(session.master), attrs)

    def test_canonical_editing_and_input_boundary(self):
        session = self.session(cwd=REPOSITORY)
        attrs = termios.tcgetattr(session.master)
        self.file_source(session, "Diagnose EPICS connectivity", "tests/vm/pcap/epics-reads.pcap")
        session.expect(r"PV name .*?\): ")
        session.send(b"discard-me\x15WP:VALUEX\x7f\n")
        argv, _, code = self.equivalent(session)
        self.assertEqual((argv[3], code), ("WP:VALUE", 0))
        session.menu("Next action", "Inspect another PV or all EPICS activity")
        session.expect(r"PV name .*?\): ")
        # 253 UTF-8 bytes, split inside the last character, must round-trip.
        pv = "A" + "\u03a9" * 126
        data = pv.encode()
        session.send(data[:-1])
        session.pump(0.2)
        self.assertEqual(session.output.count("Command:"), 1)
        session.send(data[-1:] + b"\n")
        argv, _, code = self.equivalent(session)
        self.assertEqual((argv[3], code), (pv, 5))
        self.finish(session, 5)
        self.assertEqual(termios.tcgetattr(session.master), attrs)

    def test_rejected_input_does_not_leak_to_parent_terminal(self):
        for suffix in [b"", b"\x04REVIEW_TAIL_MARKER\n"]:
            with self.subTest(suffix=suffix):
                session = self.session(cwd=REPOSITORY, retained_input=True)
                attrs = termios.tcgetattr(session.master)
                session.expect(r"Choice: ")
                session.send(b"3" + b" " * 252 + b"XREJECTED_CURRENT_LINE\n" + suffix)
                self.assertEqual(session.wait(2), 1)
                self.assertIn("input exceeds 253 bytes", session.output)
                self.assertNotIn("Command:", session.output)
                self.assertFalse(select.select([session.retained_input], [], [], 0.2)[0],
                                 "Rejected input remains readable by the invoking terminal owner")
                self.assertEqual(termios.tcgetattr(session.master), attrs)


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        BINARY = Path(sys.argv.pop(1)).resolve()
    print(f"Binary: {BINARY}\nSHA256: {hashlib.sha256(BINARY.read_bytes()).hexdigest()}", flush=True)
    unittest.main(verbosity=2)
