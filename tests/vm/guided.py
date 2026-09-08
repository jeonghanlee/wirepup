"""Real guided CLI scenarios; called only by the guarded dedicated-VM runner."""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import termios
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guidance import Session

SESSION = Path("/run/wirepup/session.json")


class GuidedSuite:
    def __init__(self, lab):
        self.lab = lab
        self.records = []
        self.mac = json.loads(lab.run(["ip", "-j", "link", "show", "wp0"], lab.CLIENT).stdout)[0]["address"]

    @contextlib.contextmanager
    def terminal(self, name, prefix=()):
        session = Session(self.lab.command([*prefix, self.lab.WP], self.lab.CLIENT))
        try:
            yield session
        finally:
            session.close()
            (self.lab.OUT / (name + ".pty.log")).write_text(session.output)

    def check(self, name, action):
        start = time.monotonic()
        try:
            detail = action() or "All assertions passed"
            state = "PASS"
        except Exception as error:
            detail, state = str(error), "FAIL"
        self.records.append(dict(id=name, state=state, detail=detail,
                                 elapsed_seconds=round(time.monotonic()-start, 3)))
        self.save()
        print(f"[ {state} ] {name}: {detail}", flush=True)

    def save(self):
        (self.lab.OUT / "guidance-results.json").write_text(json.dumps({
            "binary_sha256": hashlib.sha256(Path(self.lab.WP).read_bytes()).hexdigest(),
            "checks": self.records}, indent=2) + "\n")

    def live(self, session, purpose="Find devices", pv="", duration="300ms"):
        session.menu("Purpose", purpose)
        session.menu("Source", "Live interface")
        block = session.expect(r"\nInterface\n.*?Choice: ").group()
        choice = re.search(r"^\s+(\d+)\s+wp0 \(", block, re.M)
        assert choice, block
        session.line(choice[1])
        if purpose == "Diagnose EPICS connectivity":
            session.answer("PV name", pv)
        session.answer("Observation duration", duration)

    def finish(self, session, code=0):
        session.menu("Next action", "Finish")
        assert session.wait() == code, session.output

    def rows(self, capture, expression, field="frame.number", growing=False):
        result = self.lab.run(["tshark", "-r", str(capture), "-Y", expression,
                               "-T", "fields", "-e", field], expect=None if growing else 0)
        # Only readiness polling may encounter an incomplete current frame.
        # Final assertions require a successful independent decode.
        return result.stdout.strip().splitlines() if result.returncode == 0 else []

    def routes(self):
        return self.lab.run(["ip", "-j", "route", "show", "table", "all"], self.lab.CLIENT).stdout

    def passive(self):
        before = self.lab.addresses()
        routes = self.lab.run(["ip", "-j", "route"], self.lab.CLIENT).stdout
        with self.lab.capture("guided-passive", self.lab.PEER, ["ether", "src", self.mac]) as capture:
            for purpose, pv in [("Find devices", ""), ("Diagnose EPICS connectivity", ""),
                                ("Diagnose EPICS connectivity", "WP:ABSENT")]:
                with self.terminal("guided-passive-" + (pv or purpose.replace(" ", "-"))) as session:
                    self.live(session, purpose, pv)
                    _, _, code = session.operation()
                    self.finish(session, code)
            with self.terminal("guided-observation-interrupt") as session:
                self.live(session, duration="30s")
                session.expect(r"\nCommand: .*?\n")
                session.process.send_signal(signal.SIGTERM)
                assert session.wait(3) == 1
                assert session.output.count("Command:") == 1
        assert not self.rows(capture, "eth.src == " + self.mac)
        assert before == self.lab.addresses()
        assert routes == self.lab.run(["ip", "-j", "route"], self.lab.CLIENT).stdout
        return "Three passive flows plus observation interruption: zero source-MAC frames; addresses/routes unchanged"

    def arp_prompt(self, session):
        self.live(session)
        session.operation()
        session.menu("Next action", "Send bounded ARP requests (active)")
        session.answer("Explicit IPv4 address", "192.0.2.2/32")
        session.expect(r"Proceed\? \[y/N\] ")

    def confirmations(self):
        before = self.lab.addresses()
        routes = self.routes()
        with self.lab.capture("guided-refusals", self.lab.PEER, ["ether", "src", self.mac]) as capture:
            for action in ["empty", "no", "eof", "partial", "SIGINT", "SIGTERM"]:
                with self.terminal("guided-refuse-" + action) as session:
                    self.arp_prompt(session)
                    if action in ("SIGINT", "SIGTERM"):
                        session.process.send_signal(getattr(signal, action))
                    elif action in ("eof", "partial"):
                        session.send(b"y\x04\x04" if action == "partial" else b"\x04")
                    else:
                        session.line("" if action == "empty" else "n")
                        assert session.operation()[2] == 1
                        self.finish(session, 1)
                    assert session.wait(3) == 1
        assert not self.rows(capture, "eth.src == " + self.mac)
        assert before == self.lab.addresses()
        assert routes == self.routes()
        return "Six confirmation refusals: no transmission; addresses and routes unchanged"

    def arp(self):
        with self.lab.capture("guided-arp", self.lab.PEER, ["arp"]) as capture:
            with self.terminal("guided-arp") as session:
                self.arp_prompt(session)
                session.line("yes")
                _, result, code = session.operation()
                assert code == 0 and "sent 1 ARP" in result and "192.0.2.2" in result, result
                self.finish(session)
        assert len(self.rows(capture, f"arp.opcode == 1 && eth.src == {self.mac}")) == 1
        assert self.rows(capture, f"arp.opcode == 1 && eth.src == {self.mac}", "arp.dst.proto_ipv4") == ["192.0.2.2"]

    def search_prompt(self, session, duration="500ms"):
        self.live(session, "Diagnose EPICS connectivity", "WP:VALUE", duration)
        session.operation()
        session.menu("Next action", "Send an explicit PV search (active)")
        session.menu("Search protocols", "CA and PVA")
        session.answer("Explicit destinations", "192.0.2.255")
        session.expect(r"Proceed\? \[y/N\] ")

    def search(self, cancel=False):
        name = "guided-search-" + str(cancel)
        with self.lab.capture(name, self.lab.PEER, ["udp"]) as capture:
            with self.terminal(name) as session:
                self.search_prompt(session, "3s" if cancel else "500ms")
                assert "one CA search to 192.0.2.255:5064" in session.output
                assert "one PVA search to 192.0.2.255:5076" in session.output
                session.line("y")
                if cancel:
                    self.lab.until(lambda: self.rows(capture, f"eth.src == {self.mac} && udp.dstport == 5064", growing=True), 3)
                    if cancel == "eof":
                        session.send(b"\x04")
                    else:
                        session.process.send_signal(signal.SIGTERM)
                    assert session.wait(3) == 1
                else:
                    _, result, code = session.operation()
                    assert code == 0 and "CA server" in result and "PVA server" in result, result
                    self.finish(session)
        assert len(self.rows(capture, f"eth.src == {self.mac} && udp.dstport == 5064")) == 1
        assert len(self.rows(capture, f"eth.src == {self.mac} && udp.dstport == 5076")) == (0 if cancel else 1)
        assert self.rows(capture, f"eth.src == {self.mac} && udp.dstport == 5064", "ip.dst") == ["192.0.2.255"]
        assert self.rows(capture, f"eth.src == {self.mac} && udp.dstport == 5076", "ip.dst") == ([] if cancel else ["192.0.2.255"])

    def privilege(self):
        with self.terminal("guided-no-privilege", ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]) as session:
            self.live(session)
            assert session.operation()[2] == 3
            session.menu("Next action", "Send bounded ARP requests (active)")
            session.answer("Explicit IPv4 address", "192.0.2.2/32")
            session.expect(r"Proceed\? \[y/N\] ")
            session.line("y")
            assert session.operation()[2] == 3
            self.finish(session, 3)
            assert "does not invoke sudo" in session.output

    def connect_prompt(self, session):
        self.live(session, duration="1s")
        session.operation()
        session.menu("Next action", "Diagnose an observed IPv4 address")
        session.menu("Observed IPv4 address", "10.44.0.2")
        session.operation()
        session.menu("Next action", "Connect temporarily to a recommended target (active)")
        session.menu("Target for temporary connection", "10.44.0.2")
        session.expect(r"Proceed\? \[y/N\] ")
        assert "then run:" in session.output and "10.44.0.254/24" in session.output
        assert "This guide will remove only" in session.output

    def entries(self):
        return json.loads(SESSION.read_text())["entries"] if SESSION.exists() else []

    def owned(self):
        return [e for e in self.entries() if e["address"] == "10.44.0.254/24"]

    def recover(self):
        self.lab.wp("disconnect", "10.44.0.254", "-i", "wp0")
        assert not self.owned()

    def lifecycle(self, ending):
        before = self.lab.addresses()
        routes = self.routes()
        records = self.entries()
        name = "guided-cleanup-" + ending
        try:
            with self.terminal(name, ["unshare", "--mount", "--propagation", "private"]) as session:
                self.connect_prompt(session)
                if ending == "before":
                    session.process.send_signal(signal.SIGTERM)
                    assert session.wait(3) == 1
                    assert not self.owned()
                    return
                if ending == "conflict":
                    self.lab.run(["ip", "address", "add", "10.44.0.254/24", "dev", "wp0"], self.lab.PEER)
                session.line("y")
                if ending == "probe":
                    time.sleep(0.25)
                    session.process.send_signal(signal.SIGTERM)
                    assert session.wait(3) == 1
                    assert not self.owned()
                    return
                code = session.operation(timeout=15)[2]
                if ending == "conflict":
                    assert code == 6, session.output
                    self.finish(session, 6)
                    return
                assert code == 0 and self.owned(), session.output
                assert any(a[1] == "10.44.0.254" for a in self.lab.addresses())
                if ending == "identity":
                    data = json.loads(SESSION.read_text())
                    next(e for e in data["entries"] if e["address"] == "10.44.0.254/24")["added_at"] = "2000-01-01T00:00:00Z"
                    SESSION.write_text(json.dumps(data))
                if ending == "label":
                    self.lab.run(["ip", "address", "del", "10.44.0.254/24", "dev", "wp0"], self.lab.CLIENT)
                    self.lab.run(["ip", "address", "add", "10.44.0.254/24", "dev", "wp0", "label", "wp0:other"], self.lab.CLIENT)
                    assert ("wp0", "10.44.0.254", 24, "wp0:other") in self.lab.addresses()
                if ending == "remove-failure":
                    # The real ip binary stays in place; a private mount makes
                    # its actual exec fail. No application operation is replaced.
                    self.lab.run(["nsenter", "-t", str(session.process.pid), "-m", "mount", "--bind", "/usr/bin/ip", "/usr/bin/ip"])
                    self.lab.run(["nsenter", "-t", str(session.process.pid), "-m", "mount", "-o", "remount,bind,noexec", "/usr/bin/ip"])
                if ending == "deadline":
                    lock = Path(str(SESSION) + ".lock").open("a")
                    fcntl.flock(lock, fcntl.LOCK_EX)
                else:
                    lock = None
                try:
                    if ending in ("SIGINT", "SIGTERM"):
                        session.process.send_signal(getattr(signal, ending))
                    elif ending == "eof":
                        session.expect(r"Next action\n.*?Choice: ")
                        session.send(b"\x04")
                    else:
                        session.menu("Next action", "Finish")
                    code = session.wait(8)
                finally:
                    if lock is not None:
                        lock.close()
                failure = ending in ("identity", "label", "remove-failure", "deadline")
                assert code == (1 if failure or ending in ("eof", "SIGINT", "SIGTERM") else 0), session.output
                if failure:
                    assert self.owned() and "Cleanup failed" in session.output and "selective recovery" in session.output
                    assert any(a[1] == "10.44.0.254" for a in self.lab.addresses())
                    self.recover()
                else:
                    assert not self.owned() and "Removed this guide's temporary address" in session.output
        finally:
            if ending == "conflict":
                self.lab.run(["ip", "address", "del", "10.44.0.254/24", "dev", "wp0"], self.lab.PEER, expect=None)
            if self.owned():
                self.recover()
            assert self.lab.addresses() == before
            assert self.entries() == records
            assert self.routes() == routes

    def interrupted_add(self, after_kernel=False):
        name = "guided-add-after-kernel" if after_kernel else "guided-add-before-kernel"
        trace = self.lab.OUT / (name + ".strace")
        # On the installed iproute2, the first sendmsg reads the link and
        # the second sends RTM_NEWADDR. Delay its actual return, not exit.
        injection = "sendmsg:delay_exit=3s:when=2" if after_kernel else "sendmsg:delay_enter=3s"
        prefix = ["strace", "-f", "-o", str(trace), "-e", "trace=execve,sendmsg,recvmsg,exit_group", "-e", "inject=" + injection]
        before, records, routes = self.lab.addresses(), self.entries(), self.routes()
        try:
            with self.terminal(name, prefix) as session:
                self.connect_prompt(session)
                session.line("y")
                self.lab.until(lambda: self.owned() and '/ip", ["/usr' in trace.read_text(), 15)
                if after_kernel:
                    self.lab.until(lambda: any(a[1] == "10.44.0.254" for a in self.lab.addresses()), 5)
                children = Path(f"/proc/{session.process.pid}/task/{session.process.pid}/children").read_text().split()
                guide = next(int(pid) for pid in children if Path(f"/proc/{pid}/exe").resolve() == Path(self.lab.WP))
                os.kill(guide, signal.SIGTERM)
                assert session.wait(5) == 1, session.output
                assert self.owned(), "Uncertain add lost its recovery record"
                assert "Recovery command:" in session.output and "outcome" in session.output.lower()
                self.recover()
        finally:
            if self.owned():
                self.recover()
            assert self.lab.addresses() == before
            assert self.entries() == records
            assert self.routes() == routes

    def eof_during_probe(self):
        before, records, routes = self.lab.addresses(), self.entries(), self.routes()
        with self.lab.capture("guided-probe-eof", self.lab.PEER, ["arp"]) as capture:
            with self.terminal("guided-probe-eof") as session:
                self.connect_prompt(session)
                session.line("y")
                sent = f"eth.src == {self.mac} && arp.src.proto_ipv4 == 0.0.0.0"
                self.lab.until(lambda: self.rows(capture, sent, growing=True), 3)
                session.send(b"\x04")
                assert session.wait(3) == 1
                assert not self.owned()
        targets = self.rows(capture, sent, "arp.dst.proto_ipv4")
        assert 1 <= len(targets) <= 3 and set(targets) == {"10.44.0.254"}, targets
        assert self.lab.addresses() == before and self.entries() == records
        assert self.routes() == routes

    def subprocess_deadline(self):
        before, records, routes = self.lab.addresses(), self.entries(), self.routes()
        trace = self.lab.OUT / "guided-cleanup-child-deadline.strace"
        prefix = ["strace", "-f", "-o", str(trace), "-e", "trace=execve,sendmsg,exit_group",
                  "-e", "inject=sendmsg:delay_enter=6s:when=1"]
        try:
            with self.terminal("guided-cleanup-child-deadline", prefix) as session:
                self.connect_prompt(session)
                session.line("y")
                assert session.operation(timeout=20)[2] == 0 and self.owned(), session.output
                started = time.monotonic()
                session.menu("Next action", "Finish")
                assert session.wait(8) == 1, session.output
                assert 4.5 <= time.monotonic() - started < 8
                assert '"address", "del"' in trace.read_text() and "killed by SIGKILL" in trace.read_text()
                assert self.owned() and any(a[1] == "10.44.0.254" for a in self.lab.addresses())
                assert "Cleanup failed" in session.output and "selective recovery" in session.output
                self.recover()
        finally:
            if self.owned():
                self.recover()
            assert self.lab.addresses() == before and self.entries() == records
            assert self.routes() == routes

    def confirmation_typeahead(self):
        before, records, routes = self.lab.addresses(), self.entries(), self.routes()
        with self.lab.capture("guided-confirmation-typeahead", self.lab.PEER, ["ether", "src", self.mac]) as capture:
            for index, pending in enumerate([b"y\n", b"xy\n", b"unfinished"]):
                with self.terminal(f"guided-confirmation-typeahead-{index}") as session:
                    self.live(session)
                    session.operation()
                    session.menu("Next action", "Send bounded ARP requests (active)")
                    session.expect(r"Explicit IPv4 address.*?\): ")
                    session.send(b"192.0.2.2/32\n" + pending)
                    session.expect(r"Proceed\? \[y/N\] ")
                    session.pump(0.3)
                    assert session.process.poll() is None
                    assert session.output.count("Operation finished") == 1, session.output
                    session.line("n")
                    assert session.operation()[2] == 1
                    self.finish(session, 1)
        assert not self.rows(capture, "eth.src == " + self.mac)
        assert self.lab.addresses() == before and self.entries() == records
        assert self.routes() == routes

    def overlong_confirmations(self):
        before, records, routes = self.lab.addresses(), self.entries(), self.routes()
        with self.lab.capture("guided-overlong-confirmations", self.lab.PEER, ["ether", "src", self.mac]) as capture:
            for size in (5000, 253):
                for direct in (False, True):
                    name = f"overlong-confirmation-{size}-{direct}"
                    argv = self.lab.command([self.lab.WP, "probe", "-i", "wp0", "--arp", "192.0.2.2/32"], self.lab.CLIENT)
                    session = Session(argv if direct else self.lab.command([self.lab.WP], self.lab.CLIENT))
                    try:
                        attrs = termios.tcgetattr(session.master)
                        assert attrs[3] & termios.ICANON
                        if direct:
                            session.expect(r"Proceed\? \[y/N\] ")
                        else:
                            self.arp_prompt(session)
                        session.send(b"y" + b" " * size + b"n\n")
                        assert session.wait(3) == 1, session.output
                        assert "input exceeds 253 bytes" in session.output, session.output
                        assert termios.tcgetattr(session.master) == attrs
                    finally:
                        session.close()
                        (self.lab.OUT / (name + ".pty.log")).write_text(session.output)
        assert not self.rows(capture, "eth.src == " + self.mac)
        assert self.lab.addresses() == before and self.entries() == records
        assert self.routes() == routes
        return "Overlong guided/direct confirmations refused; zero source-MAC frames; terminal/configuration unchanged"

    def shared_subnet_cleanup(self, promotion):
        before, records, routes = self.lab.addresses(), self.entries(), self.routes()
        keys = ["net.ipv4.conf.all.promote_secondaries", "net.ipv4.conf.wp0.promote_secondaries"]
        saved = {key: self.lab.run(["sysctl", "-n", key], self.lab.CLIENT).stdout.strip() for key in keys}
        manual = "10.44.0.253/24"
        added_manual = False
        try:
            for key in keys:
                self.lab.run(["sysctl", "-qw", f"{key}={promotion}"], self.lab.CLIENT)
            with self.terminal(f"shared-subnet-{promotion}") as session:
                self.connect_prompt(session)
                session.line("y")
                assert session.operation()[2] == 0 and self.owned(), session.output
                self.lab.run(["ip", "address", "add", manual, "dev", "wp0"], self.lab.CLIENT)
                added_manual = True
                addresses = self.lab.addresses()
                raw = self.lab.run(["ip", "-j", "-4", "address"], self.lab.CLIENT).stdout
                during_routes, during_session = self.routes(), SESSION.read_bytes()
                session.menu("Next action", "Finish")
                assert session.wait(3) == 1, session.output
                assert "primary address has another address in its subnet" in session.output
                assert "Resolve the reported condition" in session.output
                assert "Removed this guide's" not in session.output
                assert self.lab.addresses() == addresses
                assert self.lab.run(["ip", "-j", "-4", "address"], self.lab.CLIENT).stdout == raw
                assert self.routes() == during_routes and SESSION.read_bytes() == during_session
                for key in keys:
                    assert self.lab.run(["sysctl", "-n", key], self.lab.CLIENT).stdout.strip() == str(promotion)
        finally:
            # Remove only this test's manual secondary before using the weaker
            # direct recovery command, so the primary cannot take it with it.
            if added_manual:
                self.lab.run(["ip", "address", "del", manual, "dev", "wp0"], self.lab.CLIENT, expect=None)
            if self.owned():
                self.recover()
            for key, value in saved.items():
                self.lab.run(["sysctl", "-qw", f"{key}={value}"], self.lab.CLIENT)
            assert self.lab.addresses() == before and self.entries() == records
            assert self.routes() == routes
        return f"Promotion={promotion}: refusal preserved all addresses, routes, complete session and sysctls; later selective recovery passed"

    def owned_secondary_cleanup(self):
        before, records, routes = self.lab.addresses(), self.entries(), self.routes()
        keys = ["net.ipv4.conf.all.promote_secondaries", "net.ipv4.conf.wp0.promote_secondaries"]
        saved = {key: self.lab.run(["sysctl", "-n", key], self.lab.CLIENT).stdout.strip() for key in keys}
        manual = "10.44.0.253/24"
        added_manual = False
        evidence = {"state": "FAIL"}

        def state():
            return {"addresses": json.loads(self.lab.run(["ip", "-j", "-4", "address"], self.lab.CLIENT).stdout),
                    "routes": json.loads(self.routes()), "entries": self.entries(),
                    "session": json.loads(SESSION.read_text()) if SESSION.exists() else None}

        try:
            for key in keys:
                self.lab.run(["sysctl", "-qw", f"{key}=0"], self.lab.CLIENT)
            with self.terminal("owned-secondary-cleanup") as session:
                self.connect_prompt(session)
                # Establish a real primary before the confirmed add, without
                # changing the chosen candidate or fabricating its Entry.
                self.lab.run(["ip", "address", "add", manual, "dev", "wp0"], self.lab.CLIENT)
                added_manual = True
                evidence["before_add"] = state()
                session.line("y")
                assert session.operation()[2] == 0 and self.owned(), session.output
                evidence["after_add"] = state()
                live = [a for link in evidence["after_add"]["addresses"] for a in link["addr_info"]]
                assert next(a for a in live if a["local"] == "10.44.0.254").get("secondary") is True
                assert not next(a for a in live if a["local"] == "10.44.0.253").get("secondary", False)
                session.menu("Next action", "Finish")
                assert session.wait(8) == 0, session.output
                assert "Removed this guide's temporary address" in session.output
                evidence["after_finish"] = state()
                assert evidence["after_finish"] == evidence["before_add"], evidence
                for key in keys:
                    assert self.lab.run(["sysctl", "-n", key], self.lab.CLIENT).stdout.strip() == "0"
                evidence["state"] = "PASS"
        finally:
            (self.lab.OUT / "owned-secondary-results.json").write_text(json.dumps(evidence, indent=2) + "\n")
            # Recover the owned secondary before removing the manual primary.
            if self.owned():
                self.recover()
            if added_manual:
                self.lab.run(["ip", "address", "del", manual, "dev", "wp0"], self.lab.CLIENT)
            for key, value in saved.items():
                self.lab.run(["sysctl", "-qw", f"{key}={value}"], self.lab.CLIENT)
            assert self.lab.addresses() == before and self.entries() == records
            assert self.routes() == routes
        return "Owned secondary removed at exit 0; manual primary, routes, other entries and sysctls preserved"

    def run(self):
        self.check("G01-passive", self.passive)
        self.check("G02-confirmation-refusals", self.confirmations)
        self.check("G03-arp", self.arp)
        self.check("G04-search", self.search)
        self.check("G05-search-cancellation", lambda: self.search(True))
        self.check("G06-privilege", self.privilege)
        # Controls are established by real iproute2 and direct WirePup commands.
        self.lab.run(["ip", "address", "add", "192.0.2.99/24", "dev", "wp0"], self.lab.CLIENT)
        self.lab.wp("connect", "-i", "wp0", "--address", "192.0.2.98/24", "--yes")
        self.lab.run(["ip", "address", "add", "10.44.0.2/24", "dev", "wp0"], self.lab.PEER)
        traffic = self.lab.spawn(["ping", "-I", "10.44.0.2", "-i", "0.1", "10.44.0.99"], "guided-peer-traffic", self.lab.PEER)
        refresh = self.lab.spawn(["python3", "-c", "import subprocess,time\nwhile True:\n subprocess.run(['ip','neigh','flush','dev','wp0'],check=True)\n time.sleep(0.2)\n"], "guided-peer-neighbor-refresh", self.lab.PEER)
        try:
            for index, ending in enumerate(["quit", "eof", "SIGINT", "SIGTERM", "before", "probe", "conflict", "identity", "label", "remove-failure", "deadline"], 7):
                self.check(f"G{index:02}-{ending}", lambda ending=ending: self.lifecycle(ending))
            self.check("G18-add-before-kernel", self.interrupted_add)
            self.check("G19-add-after-kernel", lambda: self.interrupted_add(True))
            self.check("G20-search-eof", lambda: self.search("eof"))
            self.check("G21-probe-eof", self.eof_during_probe)
            self.check("G22-cleanup-child-deadline", self.subprocess_deadline)
            self.check("G23-confirmation-typeahead", self.confirmation_typeahead)
            self.check("G24-overlong-confirmations", self.overlong_confirmations)
            self.check("G25-shared-subnet-promotion-off", lambda: self.shared_subnet_cleanup(0))
            self.check("G26-shared-subnet-promotion-on", lambda: self.shared_subnet_cleanup(1))
            self.check("G27-owned-secondary", self.owned_secondary_cleanup)
        finally:
            self.lab.stop(refresh)
            self.lab.stop(traffic)
            self.lab.run(["ip", "address", "del", "10.44.0.2/24", "dev", "wp0"], self.lab.PEER)
            self.lab.wp("disconnect", "192.0.2.98", "-i", "wp0")
            self.lab.run(["ip", "address", "del", "192.0.2.99/24", "dev", "wp0"], self.lab.CLIENT)
        failed = [r["id"] for r in self.records if r["state"] != "PASS"]
        assert not failed, failed
        return f"{len(self.records)} real guided scenarios passed; see guidance-results.json"


def run_guided(lab):
    return GuidedSuite(lab).run()
