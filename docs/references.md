# Technical References

These are starting references for protocol implementation and validation.

## EPICS

### Channel Access protocol

EPICS Documentation:

https://docs.epics-controls.org/en/latest/internal/ca_protocol.html

Relevant defaults:

```text
CA server/search:   5064
CA repeater/beacon: 5065
```

### Channel Access configuration/troubleshooting

https://docs.epics-controls.org/en/latest/ca-ref/configuration.html

https://docs.epics-controls.org/en/latest/ca-ref/troubleshooting.html

### PVAccess protocol

https://docs.epics-controls.org/en/latest/pv-access/protocol.html

### PVAccess PV name resolution

https://docs.epics-controls.org/en/latest/pv-access/PV-Name-Resolution.html

Relevant defaults:

```text
PVA UDP search/broadcast: 5076
PVA TCP server:           5075
```

## Addressing/discovery

### IPv4 Link-Local

RFC 3927 — Dynamic Configuration of IPv4 Link-Local Addresses

https://www.rfc-editor.org/rfc/rfc3927

### IPv4 Address Conflict Detection / ARP probing

RFC 5227 — IPv4 Address Conflict Detection

https://www.rfc-editor.org/rfc/rfc5227

### DHCPv4

RFC 2131 — Dynamic Host Configuration Protocol

https://www.rfc-editor.org/rfc/rfc2131

### IPv6 Neighbor Discovery

RFC 4861 — Neighbor Discovery for IP version 6

https://www.rfc-editor.org/rfc/rfc4861

### IPv6 Stateless Address Autoconfiguration

RFC 4862

https://www.rfc-editor.org/rfc/rfc4862

## Ethernet

### LLDP

IEEE 802.1AB

### VLAN

IEEE 802.1Q

Implementation should use authoritative standards/specifications and packet captures rather than relying only on port-number conventions.
