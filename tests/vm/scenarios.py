#!/usr/bin/python3
"""Real-path scenarios confined to a dedicated libvirt guest.

No WirePup function is replaced. Linux, dnsmasq, dhcpcd, and PVXS are
the packet peers. Raw output and independent tcpdump captures are retained.
"""
import argparse
import contextlib
import csv
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

WP = "/usr/local/bin/wirepup"
IOC = "/opt/wirepup-epics/bin/softIocPVX"
NS = ["wpl-switch", "wpl-client", "wpl-peer", "wpl-ioc2", "wpl-dhcp"]
CLIENT, PEER, IOC2, DHCP = NS[1:]
PV = "WP:VALUE"
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
PROCS = []
RECORDS = []
COUNTER = 0
OUT = None


def command(args, ns=None):
    return (["ip", "netns", "exec", ns] if ns else []) + list(args)


def run(args, ns=None, expect=0, timeout=20, env=None):
    global COUNTER
    COUNTER += 1
    prefix = OUT / f"command-{COUNTER:03}"
    argv = command(args, ns)
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    prefix.with_suffix(".out").write_text(result.stdout)
    prefix.with_suffix(".err").write_text(result.stderr)
    with (OUT / "commands.jsonl").open("a") as stream:
        stream.write(json.dumps({"argv": argv, "exit": result.returncode,
                                 "stdout": prefix.name + ".out", "stderr": prefix.name + ".err"}) + "\n")
    if expect is not None:
        assert result.returncode == expect, (argv, result.returncode, result.stderr)
    return result


def spawn(args, name, ns=None, env=None):
    argv = command(args, ns)
    stream = (OUT / f"{name}.log").open("w")
    process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, start_new_session=True, env=env)
    stream.close()
    PROCS.append(process)
    with (OUT / "commands.jsonl").open("a") as ledger:
        ledger.write(json.dumps({"argv": argv, "pid": process.pid, "log": name + ".log"}) + "\n")
    return process


def stop(process, sig=signal.SIGTERM):
    if process.poll() is None:
        os.killpg(process.pid, sig)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def until(predicate, seconds=10):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("readiness deadline expired")


def log_ready(name, text, process):
    def ready():
        assert process.poll() is None, (name, (OUT / (name + ".log")).read_text())
        return text in (OUT / (name + ".log")).read_text()
    until(ready)


@contextlib.contextmanager
def capture(name, ns=CLIENT, expression=None, iface="wp0"):
    args = ["tcpdump", "--immediate-mode", "-U", "-n", "-i", iface, "-w", str(OUT / (name + ".pcap"))]
    if expression:
        args += expression
    process = spawn(args, name + "-tcpdump", ns)
    log_ready(name + "-tcpdump", "listening on", process)
    try:
        yield OUT / (name + ".pcap")
    finally:
        stop(process, signal.SIGINT)


def wp(*args, ns=CLIENT, expect=0, timeout=20):
    return run([WP, *args], ns, expect, timeout)


def addresses(ns=CLIENT):
    items = json.loads(run(["ip", "-j", "-4", "address"], ns).stdout)
    return sorted((i["ifname"], a["local"], a["prefixlen"], a.get("label", ""))
                  for i in items for a in i.get("addr_info", []))


def report_codes(report):
    return {f["code"] for section in ("observed", "inferred", "recommended", "executed")
            for f in report.get(section, [])}


def check(identity, action):
    started = time.time()
    try:
        detail = action() or "All assertions passed"
        state = "PASS"
    except Exception as error:
        detail, state = str(error), "FAIL"
    RECORDS.append({"id": identity, "state": state, "detail": detail,
                    "started_at": started, "elapsed_seconds": round(time.time() - started, 3)})
    print(f"[ {state} ] {identity}: {detail}", flush=True)
    save()


def save():
    (OUT / "results.json").write_text(json.dumps({
        "suite": "vm-scenarios", "runner": "installed", "os": "debian-13",
        "arch": os.uname().machine, "run": OUT.name,
        "binary_sha256": hashlib.sha256(Path(WP).read_bytes()).hexdigest(),
        "checks": RECORDS}, indent=2) + "\n")


def setup():
    existing = {line.split()[0] for line in run(["ip", "netns", "list"]).stdout.splitlines()}
    assert not existing.intersection(NS), "Dedicated suite namespaces already exist"
    for ns in NS:
        run(["ip", "netns", "add", ns])
        run(["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"], ns)
        run(["sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"], ns)
        run(["ip", "link", "set", "lo", "up"], ns)
    run(["ip", "link", "add", "br0", "type", "bridge"], NS[0])
    run(["ip", "link", "set", "br0", "up"], NS[0])
    for number, ns in enumerate(NS[1:], 1):
        edge, leaf = f"wple{number}", f"wpll{number}"
        run(["ip", "link", "add", edge, "type", "veth", "peer", "name", leaf])
        run(["ip", "link", "set", edge, "netns", NS[0]])
        run(["ip", "link", "set", leaf, "netns", ns])
        run(["ip", "link", "set", edge, "master", "br0"], NS[0])
        run(["ip", "link", "set", edge, "up"], NS[0])
        run(["ip", "link", "set", leaf, "name", "wp0"], ns)
        run(["ip", "link", "set", "wp0", "up"], ns)
        run(["ip", "address", "add", f"192.0.2.{number}/24", "brd", "+", "dev", "wp0"], ns)


def isolation():
    for ns in NS[1:]:
        assert not run(["ip", "route", "show", "default"], ns).stdout
        assert len(json.loads(run(["ip", "-j", "link"], ns).stdout)) == 2


def live_arp():
    process = spawn([WP, "capture", "-i", "wp0", "--protocol", "arp", "--timeout", "3s",
                     "-o", str(OUT / "live-arp.pcap")], "live-capture", CLIENT)
    log_ready("live-capture", "Capturing on", process)
    run(["ip", "neigh", "flush", "dev", "wp0"], PEER)
    run(["ping", "-c", "1", "-W", "1", "192.0.2.1"], PEER)
    assert process.wait(timeout=7) == 0
    decoded = wp("read", str(OUT / "live-arp.pcap"), "--protocol", "arp", "--json", "--quiet").stdout
    assert "192.0.2.2" in decoded
    oracle = run(["tshark", "-r", str(OUT / "live-arp.pcap"), "-Y", "arp", "-T", "fields", "-e", "arp.src.proto_ipv4"]).stdout
    assert "192.0.2.2" in oracle


def sweep():
    data = json.loads(wp("probe", "-i", "wp0", "--arp", "192.0.2.2/32", "--yes", "--json").stdout)
    assert "arp-reply" in report_codes(data)


def lifecycle():
    run(["ip", "address", "add", "192.0.2.99/24", "dev", "wp0"], CLIENT)
    before = addresses()
    wp("connect", "-i", "wp0", "--address", "192.0.2.10/24", "--yes")
    assert any(a[1] == "192.0.2.10" for a in addresses())
    wp("disconnect", "192.0.2.10", "-i", "wp0")
    assert addresses() == before
    run(["ip", "address", "del", "192.0.2.99/24", "dev", "wp0"], CLIENT)


def conflict():
    before = addresses()
    wp("connect", "-i", "wp0", "--address", "192.0.2.2/24", "--yes", expect=6)
    assert addresses() == before


def automatic():
    run(["ip", "address", "add", "10.44.0.2/24", "dev", "wp0"], PEER)
    process = spawn([WP, "connect", "10.44.0.2", "-i", "wp0", "--timeout", "3s", "--yes"], "automatic", CLIENT)
    log_ready("automatic", "Observing", process)
    run(["ping", "-I", "10.44.0.2", "-c", "2", "-W", "1", "10.44.0.99"], PEER, expect=None)
    assert process.wait(timeout=15) == 0, (OUT / "automatic.log").read_text()
    assigned = [a[1] for a in addresses() if a[1].startswith("10.44.0.")]
    assert assigned
    wp("disconnect", assigned[0], "-i", "wp0")
    run(["ip", "address", "del", "10.44.0.2/24", "dev", "wp0"], PEER)
    return "Recommended and assigned " + assigned[0] + "; then removed"


def passive():
    mac = json.loads(run(["ip", "-j", "link", "show", "wp0"], CLIENT).stdout)[0]["address"]
    cases = [["observe"], ["discover"], ["capture", "-o", str(OUT / "passive-capture.pcap")],
             ["diagnose"], ["epics", "observe"], ["epics", "find", "WP:ABSENT"]]
    for index, args in enumerate(cases):
        with capture(f"passive-{index}", PEER, ["ether", "src", mac]):
            wp(*args, "-i", "wp0", "--timeout", "2s", "--quiet", expect=5 if "find" in args else 0)
        rows = run(["tshark", "-r", str(OUT / f"passive-{index}.pcap"), "-T", "fields", "-e", "frame.number"]).stdout
        assert not rows.strip(), (args, rows)
    return "Six passive commands: zero source-MAC frames at peer, idle isolated segment"


def dhcp(success):
    suffix = OUT.name[-5:]
    iface = ("dh" if success else "dn") + suffix
    current = "wp0" if success else "dh" + suffix
    run(["ip", "address", "flush", "dev", current], DHCP)
    run(["ip", "link", "set", current, "name", iface], DHCP)
    server = None
    if success:
        server = spawn(["dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--port=0", "--interface=wp0",
                        "--bind-interfaces", "--dhcp-range=192.0.2.100,192.0.2.110,255.255.255.0,1h",
                        "--dhcp-option=3", "--dhcp-option=6", "--dhcp-authoritative",
                        "--dhcp-leasefile=" + str(OUT / "dnsmasq.leases"), "--log-dhcp", "--log-facility=-"], "dnsmasq", PEER)
    name = "dhcp-success" if success else "dhcp-no-offer"
    conf = OUT / (name + ".conf")
    conf.write_text("nohook resolv.conf,hostname,ntp.conf\nnoipv6\n")
    client = None
    try:
        if server:
            until(lambda: ":67" in run(["ss", "-lun"], PEER).stdout)
            assert server.poll() is None
        with capture(name, DHCP, iface=iface):
            client = spawn(["dhcpcd", "-4", "-B", "-d", "-f", str(conf), "-t", "20", iface], name + "-client", DHCP)
            time.sleep(12 if success else 25)
            actual = addresses(DHCP)
            stop(client)
            time.sleep(2.2)
            run(["ping", "-c", "1", "-W", "1", "192.0.2.77"], PEER, expect=None)
    finally:
        if client:
            stop(client)
        if server:
            stop(server)
    decoded = wp("read", str(OUT / (name + ".pcap")), "--json", "--quiet").stdout
    diagnosis = json.loads(wp("diagnose", "--pcap", str(OUT / (name + ".pcap")), "--local", "192.0.2.1/24", "--json", "--quiet").stdout)
    if success:
        events = [json.loads(line) for line in decoded.splitlines()]
        assert any(e.get("fields", {}).get("message_type") == "ack" for e in events), decoded[-2000:]
        assert any(a[1].startswith("192.0.2.10") for a in actual), actual
    else:
        assert "dhcp-discover-no-offer" in report_codes(diagnosis), diagnosis
        assert any(a[1].startswith("169.254.") for a in actual), actual
    return str(actual)


def ioc_start(ns, number):
    db = OUT / "lab.db"
    db.write_text('record(ai, "WP:VALUE") {\n    field(VAL, "42")\n}\n')
    env = dict(os.environ, LD_LIBRARY_PATH="/opt/wirepup-epics/lib", EPICS_CA_AUTO_ADDR_LIST="NO",
               EPICS_CA_ADDR_LIST="192.0.2.255", EPICS_CAS_INTF_ADDR_LIST=f"192.0.2.{number}",
               EPICS_CAS_AUTO_BEACON_ADDR_LIST="NO", EPICS_CAS_BEACON_ADDR_LIST="192.0.2.255",
               EPICS_PVAS_INTF_ADDR_LIST=f"192.0.2.{number}", EPICS_PVAS_AUTO_BEACON_ADDR_LIST="NO",
               EPICS_PVAS_BEACON_ADDR_LIST="192.0.2.255")
    process = spawn([IOC, "-D", "/opt/wirepup-epics/dbd/softIocPVX.dbd", "-S", "-d", str(db)], f"ioc-{number}", ns, env)
    until(lambda: ":5064" in run(["ss", "-lun"], ns).stdout)
    assert process.poll() is None
    return process


def clients():
    env = dict(os.environ, EPICS_CA_AUTO_ADDR_LIST="NO", EPICS_CA_ADDR_LIST="192.0.2.255",
               EPICS_PVA_AUTO_ADDR_LIST="NO", EPICS_PVA_ADDR_LIST="192.0.2.255")
    with capture("epics-reads"):
        assert "42" in run(["caget", "-t", "-w", "3", PV], CLIENT, env=env).stdout
        assert "42" in run(["pvget", "-w", "3", PV], CLIENT, env=env).stdout
    result = wp("epics", "find", PV, "--pcap", str(OUT / "epics-reads.pcap"), "--json", "--quiet")
    assert {"ca-search-answer", "pva-search-answer"} <= report_codes(json.loads(result.stdout)), result.stdout


def active_search(duplicate=False):
    for protocol in ("ca", "pva"):
        with capture(("duplicate-" if duplicate else "active-") + protocol):
            result = wp("epics", "find", PV, "--active", "--to", "192.0.2.255", "--search", protocol,
                        "--timeout", "2s", "--yes", "--json")
        codes = report_codes(json.loads(result.stdout))
        assert protocol + ("-multiple-servers" if duplicate else "-search-answer") in codes, result.stdout


def missing():
    with capture("missing-pv"):
        env = dict(os.environ, EPICS_CA_AUTO_ADDR_LIST="NO", EPICS_CA_ADDR_LIST="192.0.2.255")
        run(["caget", "-w", "3", "WP:ABSENT"], CLIENT, expect=None, env=env)
    result = json.loads(wp("diagnose", "--epics", "--pcap", str(OUT / "missing-pv.pcap"), "--json", "--quiet").stdout)
    assert "ca-search-no-response" in report_codes(result), result
    wp("epics", "find", "WP:ABSENT", "--active", "--to", "192.0.2.255", "--search", "ca,pva", "--yes", "--timeout", "1s", expect=5)


def interrupt():
    before = addresses()
    process = spawn([WP, "capture", "-i", "wp0", "-o", str(OUT / "interrupted.pcap")], "interrupt-capture", CLIENT)
    log_ready("interrupt-capture", "Capturing on", process)
    stop(process, signal.SIGINT)
    assert process.returncode == 0
    wp("read", str(OUT / "interrupted.pcap"), "--quiet")
    process = spawn([WP, "connect", "-i", "wp0", "--address", "192.0.2.20/24", "--yes"], "interrupt-connect", CLIENT)
    log_ready("interrupt-connect", "ACTIVE:", process)
    stop(process, signal.SIGINT)
    assert addresses() == before
    wp("disconnect", "192.0.2.20", "-i", "wp0")


def main():
    global OUT
    parser = argparse.ArgumentParser()
    parser.add_argument("--reboot-check", type=Path)
    args = parser.parse_args()
    os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    assert os.geteuid() == 0 and os.uname().nodename == "lab-debian13-wirepup"
    os.umask(0o077)
    OUT = Path(tempfile.mkdtemp(prefix="wirepup-scenarios-", dir="/var/tmp"))
    if args.reboot_check:
        saved = json.loads((args.reboot_check / "results.json").read_text())
        RECORDS.extend(saved["checks"])
        def recovery():
            assert saved["binary_sha256"] == hashlib.sha256(Path(WP).read_bytes()).hexdigest(), "Binary changed across reboot"
            assert Path("/proc/sys/kernel/random/boot_id").read_text() != (args.reboot_check / "boot-id").read_text()
            assert not set(NS).intersection(line.split()[0] for line in run(["ip", "netns", "list"]).stdout.splitlines())
            assert not Path("/run/wirepup/session.json").exists()
            wp("disconnect", "--json", ns=None)
        RECORDS[:] = [r for r in RECORDS if r["id"] != "V16"]
        check("V16", recovery)
        print("RESULTS=" + str(OUT), flush=True)
        if any(r["state"] in ("FAIL", "SCRIPT_ERROR") for r in RECORDS):
            raise SystemExit(1)
        return
    catalog = list(csv.DictReader((ROOT / "catalog.csv").open()))
    assert [r["id"] for r in catalog] == [f"V{n:02}" for n in range(1, 18)]
    before = addresses(ns=None)
    routes = run(["ip", "-j", "-4", "route"]).stdout
    if Path("/run/wirepup/session.json").exists():
        assert json.loads(Path("/run/wirepup/session.json").read_text())["entries"] == [], "Unfinished address record exists"
    try:
        check("V01", lambda: run([WP, "version"]).stdout.strip())
        setup()
        check("V02", isolation)
        check("V03", live_arp)
        check("V04", sweep)
        check("V05", lifecycle)
        check("V06", conflict)
        check("V07", automatic)
        check("V08", passive)
        check("V09", lambda: dhcp(True))
        check("V10", lambda: dhcp(False))
        ioc_start(PEER, 2)
        check("V11", clients)
        check("V12", active_search)
        second = ioc_start(IOC2, 3)
        check("V13", lambda: active_search(True))
        stop(second)
        check("V14", missing)
        check("V15", interrupt)
        from guided import run_guided
        check("V17", lambda: run_guided(sys.modules[__name__]))
        wp("connect", "-i", "wp0", "--address", "192.0.2.30/24", "--yes")
        (OUT / "boot-id").write_text(Path("/proc/sys/kernel/random/boot_id").read_text())
        (OUT / "session.before-reboot.json").write_text(Path("/run/wirepup/session.json").read_text())
        RECORDS.append({"id": "V16", "state": "PENDING", "detail": "Address recorded; actual VM reboot and --reboot-check required"})
        assert before == addresses(ns=None), "Management addresses changed"
        assert routes == run(["ip", "-j", "-4", "route"]).stdout, "Management routes changed"
    finally:
        for process in reversed(PROCS):
            stop(process)
        done = {r["id"] for r in RECORDS}
        for row in catalog:
            if row["id"] not in done:
                RECORDS.append({"id": row["id"], "state": "SCRIPT_ERROR", "detail": "Not reached"})
        save()
        print("RESULTS=" + str(OUT), flush=True)
    if any(r["state"] in ("FAIL", "SCRIPT_ERROR") for r in RECORDS):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
