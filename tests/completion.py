"""Exercise real Readline Tab completion without executing the edited command."""

import errno
import os
from pathlib import Path
import pty
import re
import select
import shlex
import subprocess
import sys
import tempfile
import time
import unittest

REPOSITORY = Path(__file__).resolve().parent.parent
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else REPOSITORY / "bin" / "wirepup"
COMPLETION = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else REPOSITORY / "completions" / "wirepup.bash"


class ReadlineCompletion(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="wirepup-tab-")
        self.root = Path(self.workspace.name)
        self.capture = self.root / "a capture.pcap"
        self.capture.touch()
        (self.root / "a:colon.pcap").touch()
        (self.root / "a=equal.pcap").touch()
        (self.root / "-input.pcap").touch()
        (self.root / "-colon:name.pcap").touch()
        (self.root / "-equals=name.pcap").touch()

    def tearDown(self):
        self.workspace.cleanup()

    def tab(self, line, autoload=False):
        master, slave = pty.openpty()
        env = dict(os.environ, PATH=f"{BINARY.parent}:{os.environ['PATH']}", TERM="dumb")
        env["BASH_COMPLETION_USER_DIR"] = str(COMPLETION.parent.parent)
        process = subprocess.Popen(
            ["bash", "--noprofile", "--norc", "-i"], stdin=slave, stdout=slave, stderr=slave,
            cwd=self.root, env=env,
        )
        os.close(slave)

        def receive(pattern):
            data = b""
            deadline = time.monotonic() + 10
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
                data += chunk
                match = re.search(pattern, data)
                if match:
                    return match
            self.fail(f"Bash did not produce {pattern!r}: {data!r}")

        setup = (
            "unset PROMPT_COMMAND; PS1='WIREPUP_TEST> '; "
            "bind 'set enable-bracketed-paste off'; bind 'set bell-style none'; "
            "function _wirepup_readline_result { printf '\\nRESULT[%s]END\\n' \"$READLINE_LINE\"; }; "
            "bind -x '\"\\C-x\\C-r\":_wirepup_readline_result'; "
        )
        if autoload:
            setup += "source /usr/share/bash-completion/bash_completion"
        else:
            setup += f"source {shlex.quote(str(COMPLETION))}"
        try:
            os.write(master, (setup + "\n").encode())
            receive(rb"\r?\nWIREPUP_TEST> ")
            os.write(master, line.encode() + b"\t\x18\x12")
            match = receive(rb"\r?\nRESULT\[(.*?)\]END\r?\n")
            return shlex.split(match.group(1).decode())
        finally:
            os.write(master, b"\x15exit\n")
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            os.close(master)

    def test_commands_options_and_values(self):
        cases = [
            ("wirepup cap", ["wirepup", "capture"]),
            ("wirepup epics fi", ["wirepup", "epics", "find"]),
            ("wirepup observe --js", ["wirepup", "observe", "--json"]),
            ("wirepup observe --protocol=ll", ["wirepup", "observe", "--protocol=lldp"]),
            ("wirepup observe --protocol\\=ll", ["wirepup", "observe", "--protocol=lldp"]),
            ("wirepup observe '--protocol=ll", ["wirepup", "observe", "--protocol=lldp"]),
            ('wirepup observe "--protocol=ll', ["wirepup", "observe", "--protocol=lldp"]),
            ("wirepup observe '--json=f", ["wirepup", "observe", "--json=false"]),
            ("wirepup observe --protocol arp,ll", ["wirepup", "observe", "--protocol", "arp,lldp"]),
            ("wirepup epics find DEMO:PV --se", ["wirepup", "epics", "find", "DEMO:PV", "--search"]),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(self.tab(line), expected)

    def test_quoted_and_escaped_capture_paths(self):
        cases = [
            ("wirepup read a\\ c", ["wirepup", "read", "a capture.pcap"]),
            ("wirepup read -- a\\ c", ["wirepup", "read", "--", "a capture.pcap"]),
            ("wirepup read -- -in", ["wirepup", "read", "--", "./-input.pcap"]),
            ("wirepup read ./-in", ["wirepup", "read", "./-input.pcap"]),
            ("wirepup read -- -colon:na", ["wirepup", "read", "--", "-colon:na"]),
            ("wirepup read -- '-colon:na", ["wirepup", "read", "--", "./-colon:name.pcap"]),
            ("wirepup read ./-colon:na", ["wirepup", "read", "./-colon:name.pcap"]),
            ("wirepup read -- -equals=na", ["wirepup", "read", "--", "-equals=na"]),
            ("wirepup read ./-equals=na", ["wirepup", "read", "./-equals=name.pcap"]),
            ("wirepup read 'a c", ["wirepup", "read", "a capture.pcap"]),
            ('wirepup read "a c', ["wirepup", "read", "a capture.pcap"]),
            ("wirepup read a:co", ["wirepup", "read", "a:colon.pcap"]),
            ("wirepup read 'a:co", ["wirepup", "read", "a:colon.pcap"]),
            ('wirepup read "a:co', ["wirepup", "read", "a:colon.pcap"]),
            ("wirepup read a\\:co", ["wirepup", "read", "a:colon.pcap"]),
            ("wirepup read a=eq", ["wirepup", "read", "a=equal.pcap"]),
            ('wirepup read "a=eq', ["wirepup", "read", "a=equal.pcap"]),
            ("wirepup read a\\=eq", ["wirepup", "read", "a=equal.pcap"]),
            ("wirepup observe --pcap='a:co", ["wirepup", "observe", "--pcap=a:colon.pcap"]),
            ("wirepup observe --pcap=a\\ c", ["wirepup", "observe", "--pcap=a capture.pcap"]),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(self.tab(line), expected)

    @unittest.skipUnless(Path("/usr/share/bash-completion/bash_completion").is_file(),
                         "optional bash-completion package is absent")
    def test_framework_autoload(self):
        self.assertEqual(self.tab("wirepup cap", autoload=True), ["wirepup", "capture"])


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
