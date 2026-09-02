# Cross-review Prompt

Review the current WirePup repository and the other agent's proposed changes.

Do not optimize for agreement.

Check specifically for:

- hidden coupling between protocol decoders and device state;
- hidden packet transmission in passive flows;
- incorrect MAC-to-device assumptions;
- incorrect VLAN assumptions;
- unsafe privilege requirements;
- inability to replay the same logic from PCAP;
- protocol identification based only on ports;
- incorrect CA behavior/port assumptions;
- incorrect PVA behavior/port assumptions;
- diagnosis that presents inference as fact;
- architecture changes not reflected in ADRs;
- tests that require live networking unnecessarily.

Return:

1. blockers;
2. correctness issues;
3. architecture issues;
4. safety/privilege issues;
5. test gaps;
6. documentation/ADR changes required;
7. whether the change is ready to merge.
