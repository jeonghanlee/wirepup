# WirePup — Independent Full Repository Review and Repair

Review the complete WirePup repository as if you did not implement it.

Read:

* all design documentation;
* all ADRs;
* all source code;
* all tests;
* build/release configuration;
* dependency metadata.

Then build and test the project.

Your job is not only to produce a review report.

**Fix defects that can reasonably be corrected.**

Do not redesign the project merely because you prefer another style. Preserve accepted ADRs unless there is a concrete correctness, safety, or maintainability problem.

## Review areas

### Architecture

Verify:

packet
→ decoder
→ observation
→ device/session correlation
→ diagnosis
→ output

Check that protocol packages do not:

* own global device state;
* format terminal UI;
* transmit packets;
* modify local network configuration.

### Passive safety

Trace every passive command through the call graph.

Verify that these cannot transmit or change networking:

* interfaces
* observe
* discover
* capture
* read
* passive diagnose

Treat any hidden active behavior as a blocker.

### Privileges

Check:

* raw capture privileges;
* CAP_NET_RAW use;
* CAP_NET_ADMIN use;
* whether elevated privileges are broader than necessary;
* whether an untrusted parser executes unnecessarily with network-administration privilege.

### Packet parser security

Review every packet-length and offset calculation.

Test:

* truncated frames;
* malformed TLVs;
* oversized declared lengths;
* malformed CA;
* malformed PVA;
* malformed DHCP;
* malformed LLDP;
* malformed IPv6 extensions where relevant.

No network packet should be able to cause a panic or unbounded allocation.

### Concurrency

Check for:

* goroutine leaks;
* races;
* deadlocks;
* unbounded channels;
* packet backlog growth;
* clean cancellation;
* capture-source shutdown;
* dropped-packet accounting.

Run the Go race detector where practical.

### Device correlation

Verify that:

* MAC is not treated as an infallible physical-device identity;
* address history is retained correctly;
* devices are not merged based only on hostname/vendor;
* LLDP infrastructure nodes are not accidentally merged with attached endpoints;
* duplicate-IP observations remain representable.

### VLAN

Verify that the software does not claim "untagged = no VLAN".

Check capture-backend and NIC-offload limitations.

### IPv4 Link-Local

Verify:

* ARP Probe handling;
* ARP announcements;
* 169.254/16 interpretation;
* device transition from Auto-IP to another address;
* duplicate-address evidence.

### DHCP

Verify transaction correlation and handling of:

Discover
Offer
Request
ACK
NAK

### IPv6

Review:

* NDP;
* DAD;
* NS/NA;
* RS/RA;
* IPv6 address/device correlation.

### PCAP

Verify that live capture and PCAP replay use the same analysis pipeline.

Check:

* truncated packets;
* timestamps;
* interface metadata;
* PCAP/PCAPNG compatibility;
* capture length vs original length.

### EPICS Channel Access

Independently verify CA implementation against authoritative protocol documentation.

Check:

* message framing;
* byte order;
* search parsing;
* search-response correlation;
* search IDs;
* beacon behavior;
* dynamic advertised server TCP port;
* default 5064/5065 semantics;
* protocol validation beyond port number;
* multiple server/PV claims.

Treat CA protocol mistakes as blockers.

### EPICS PVAccess

Independently verify PVA implementation against authoritative protocol documentation.

Check:

* PVA headers;
* byte order;
* search;
* search response;
* beacon;
* server GUID;
* server address/port;
* default UDP 5076 / TCP 5075 semantics;
* protocol validation beyond port number.

Treat PVA protocol mistakes as blockers.

### Diagnosis engine

Every diagnosis must clearly separate:

Observed
Inferred
Recommended
Executed

Check for unjustified certainty.

"No response observed" must not be equivalent to "service/PV does not exist."

### Active discovery

Verify:

* bounded targets;
* rate limiting;
* explicit CLI intent;
* no unexpected broadcast storms;
* no aggressive default port scanning.

### Temporary IP configuration

Review extremely carefully.

Verify:

* correct interface selected;
* target subnet inference is defensible;
* candidate address avoids obvious conflicts;
* primary address is not replaced;
* routes are not unexpectedly destroyed;
* only WirePup-created state is removed;
* interrupted sessions can be recovered safely where designed;
* CAP_NET_ADMIN exposure is limited.

### Filtering

Verify consistency between:

* capture/BPF filters;
* decode filters;
* display filters;
* EPICS PV filters.

### JSON/API

Review versioned machine-readable output.

Ensure internal implementation details have not accidentally become unstable public schema.

### Privacy

Check logs and reports for unnecessary:

* packet payload;
* credentials;
* PV names;
* addresses;
* PCAP data.

### Dependencies and license

Verify:

* Apache-2.0 project license;
* dependency license compatibility;
* unnecessary dependencies;
* libpcap packaging assumptions;
* OUI data licensing.

### Tests

Evaluate coverage of:

* parsers;
* malformed input;
* PCAP replay;
* device correlation;
* diagnostics;
* active/passive separation;
* network configuration;
* CA;
* PVA;
* fuzzing.

Add missing high-value tests.

## Commands

Run appropriate project quality commands, including at minimum where supported:

go test ./...
go test -race ./...
go vet ./...

Run configured linters and fuzz smoke tests where practical.

## Repair

Fix identified correctness, security, safety, architectural, concurrency, and test defects.

Update documentation/ADRs when implementation and documentation differ.

Do not leave easily fixable blockers as comments or TODOs.

## Final output

Report:

1. blockers found and fixed;
2. correctness bugs fixed;
3. safety/privilege fixes;
4. concurrency fixes;
5. CA/PVA corrections;
6. tests added;
7. remaining real-hardware validation;
8. remaining non-blocking limitations;
9. final merge/release readiness.

The final verdict must be one of:

READY
READY WITH DOCUMENTED LIMITATIONS
NOT READY

Give concrete reasons for the verdict.

