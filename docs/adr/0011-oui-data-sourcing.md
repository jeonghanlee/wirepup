# ADR-0011: Vendor hints come from an external IEEE registry file

Status: Accepted

## Context

R-021 allows vendor identification from the MAC OUI, as a hint only. The IEEE registry changes weekly and the MA-L block alone is about 35,000 entries.

Wireshark embeds a generated `manuf` table in its binary (since 4.2 the file is no longer installed separately). That keeps lookups self-contained at the cost of a table frozen at build time and a build step that fetches from IEEE. Linux distributions ship the same registry as data packages: Debian and derivatives as `ieee-data` (`/usr/share/ieee-data/oui.txt`, with an updater), the RHEL family as `hwdata` (`/usr/share/hwdata/oui.txt`). The IEEE text format is common to both; the CSV form is Debian-only.

NFR-002 describes the intended deployment as a single executable plus optional local data files.

## Decision

WirePup does not bundle OUI data. `internal/oui` reads the IEEE MA-L text format (`oui.txt`, one `XX-XX-XX   (hex)` line per assignment) from the first location found:

1. the path given by `--oui-file`;
2. `/var/lib/ieee-data/oui.txt`;
3. `/usr/share/ieee-data/oui.txt`;
4. `/usr/share/hwdata/oui.txt`.

Only the 24-bit MA-L block is consulted in V1. MA-M and MA-S ranges (`mam.txt`, `oui36.txt`) may be added later behind the same lookup.

When no file is found, the vendor field is empty and one notice names the paths tried; this is not an error, and no command depends on the lookup.

Vendor output is labelled as a hint in every renderer and is never used by the device correlator as a merge key (R-010).

## Consequences

- The executable carries no IEEE-derived data, so the IEEE terms of use do not attach to the WirePup distribution.
- Vendor hints are as current as the host's registry copy; the `discover` JSON document records which file was read.
- The parser is a few dozen lines with one fixture; no third-party module is needed.
