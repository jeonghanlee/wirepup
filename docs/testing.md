# Testing Strategy

## 1. Principles

Most protocol logic must be testable without root and without a live network.

Testing layers:

1. byte-level unit tests;
2. complete-frame fixtures;
3. PCAP replay tests;
4. device-correlation tests;
5. diagnosis tests;
6. controlled live integration tests.

## 2. Decoder fixtures

Create fixtures for:

- Ethernet/VLAN;
- LLDP;
- ARP request/reply/probe/announcement;
- DHCP;
- IPv6 NDP/DAD;
- CA;
- PVA.

Each fixture should document its expected interpretation.

## 3. PCAP corpus

Suggested:

```text
testdata/pcap/
  lldp-single-neighbor.pcap
  arp-autoip-selection.pcap
  dhcp-success.pcap
  dhcp-no-offer.pcap
  ipv6-dad.pcap
  ca-search-response.pcap
  ca-search-no-response.pcap
  ca-beacon.pcap
  pva-search-response.pcap
  pva-beacon.pcap
  same-l2-different-subnet.pcap
```

Sanitize sensitive captures before committing.

## 4. Device correlation tests

At minimum:

- MAC observed before IP;
- IP appears later;
- Auto-IP followed by DHCP/static IP;
- one device with multiple addresses;
- two devices with same/similar hostname;
- duplicate IPv4 claims;
- LLDP switch neighbor kept distinct from endpoint device records.

## 5. Diagnosis tests

Use explicit evidence sets.

Example:

```text
Given:
  local enp3s0 = 10.20.30.51/24
  observed ARP from MAC A
  ARP sender IPv4 = 192.168.1.100

Expect:
  observed: L2 frame from MAC A on enp3s0
  inferred: MAC A appears to use 192.168.1.100
  diagnosis: IPv4 outside configured local subnet
```

## 6. CA tests

Validate semantics, not only ports.

Cases:

- valid CA search;
- valid CA search response;
- valid CA beacon;
- malformed CA message;
- UDP/5064 packet that is not CA;
- response matching prior search ID;
- apparent duplicate server claims.

## 7. PVA tests

Cases:

- valid PVA search;
- valid search response;
- server GUID extraction;
- valid beacon;
- malformed PVA message;
- UDP/5076 packet that is not PVA;
- TCP/5075 traffic without valid PVA framing.

## 8. Live integration lab

Recommended topology:

```text
Laptop
  |
small managed switch
  |---- test Linux host / IOC
  |---- embedded controller
  |---- optional second VLAN
```

Scenarios:

- no DHCP server;
- DHCP available;
- static device on different subnet;
- Auto-IP device;
- LLDP-enabled switch;
- tagged trunk/mirror capture;
- CA IOC;
- PVA IOC.

## 9. Privileged tests

CI should run parser/correlation/diagnosis tests unprivileged.

Privileged capture/network-config tests should be optional and clearly separated.
