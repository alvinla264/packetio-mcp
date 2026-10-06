# Known issues and operational limits

This document separates observed failures, environment dependencies, deliberate
bounds, and corrected historical issues. Findings from one adapter or host are
not universal device or protocol guarantees. Public documentation omits private
capture contents and device-specific credentials/configuration.

## Status summary

| Area | Status | Practical consequence |
| --- | --- | --- |
| Replies addressed to an alternate/spoofed MAC on an examined USB ECM path | Open; leading driver-level explanation identified | Spoofed-source transmission can succeed while replies remain invisible |
| Arbitrary frames on an examined WSL mirrored Ethernet path | Environment limitation; exact dropping component unresolved | Ordinary ARP/IP success does not establish custom EtherType, VLAN/QinQ or spoofing support |
| Long live calls exceeding an MCP client's deadline | Client-dependent operational limitation | Server-side capture may outlive the client's request |
| Optional tshark absent from the server's PATH | Environment dependency | Wireshark queries fail explicitly; ordinary offline reads use Scapy |
| Receive-side stripped VLAN headers | Fixed in current source | Reload/restart older server processes to obtain `PACKET_AUXDATA` restoration |
| Negative live loopback test depending on absence of DNS | Test corrected | Replies are scoped to test ARP traffic and reception is required |

## 1. Alternate-MAC reply reception on USB ECM

### Observed behavior

On one RTL8153 USB/IP setup using `r8153_ecm`:

- Raw frames with a spoofed source MAC reached the peer.
- Peer capture recorded ARP replies addressed to that alternate MAC.
- Neither this server nor concurrent standalone tshark captured those replies.
- Replies to the adapter's original MAC and broadcasts were received.
- Temporarily changing Linux's interface MAC did not restore alternate-address
  reception; restoring the original MAC restored normal exchanges.

### Leading explanation, not a validated fix

The examined driver omits the callback that propagates receive-mode changes to
the CDC device filter. Its inherited MAC handler changes the logical Linux
address without programming hardware matching. Local module inspection and
kernel configuration corroborated these source-level facts. USB control/bulk
traces or an independent wire capture are still needed to establish the exact
loss point and validate a remedy.

`promiscuous_enabled: true` means the socket membership request succeeded; it
**does not prove hardware promiscuous reception**. Likewise, zero socket drops
cannot account for packets discarded before they reach the socket.

See [Linux USB receive filtering](docs/linux-usb-receive-filtering.md) for the
source chain, candidate fixes and validation plan.

**Workaround:** use the adapter's actual source MAC for exchanges requiring
unicast replies. Qualify arbitrary-destination reception on every adapter/driver
combination. Do not silently change a user's NIC MAC or driver.

## 2. WSL mirrored Ethernet is not a transparent arbitrary-frame path

In an examined mirrored built-in Ethernet configuration, correctly formed
real-MAC ARP, IPv4 ICMP and UDP transmissions were independently observed, but
custom EtherTypes, tagged frames, spoofed-source frames and malformed IPv4 test
frames were not. Successful packet-socket sends did not establish delivery.

The exact filtering component is unresolved. Do not infer a universal EtherType
allowlist, call mirrored networking NAT, or assume every WSL version behaves the
same way. A dedicated USB adapter avoids that particular mirrored Ethernet path,
but its own USB driver/filter limitations must still be tested.

See [the README's WSL discussion](README.md#windows-laptops-and-wsl-2). Do not
change firewall, VPN, virtual-switch, bridge or routing policies without approval.

## 3. MCP client deadlines can interrupt long capture calls

A 60-second live capture exceeded one client's 60-second request deadline. The
server wrote a file, but the client did not receive the result. A requested
capture duration leaves no allowance for setup, teardown, decoding and response
serialization; reported wall-clock duration can differ from the requested
receive window.

Use a capture duration comfortably shorter than the client's deadline (for
example, 20–30 seconds for a 60-second deadline), or explicitly configure a
longer client deadline. After a timeout, verify server activity and file
completion before analyzing or starting a conflicting experiment. Do not treat
an existing file as proof of a completed, acknowledged call.

## 4. Tshark availability is scoped to the server process

The server uses Scapy for offline operations without tshark. Wireshark display
filters and tshark-backed diagnostics require a discoverable executable in the
**server's** environment.

- Inspect `describe_capabilities().tshark_available`.
- Installing or launching tshark in another shell does not change an already
  running server's PATH.
- `query_capture` reports an explicit error when tshark is unavailable.
- Ordinary reads/summaries report their backend and fallback reason.
- A separately launched server with tshark available is not evidence that the
  configured session's server has it.

Restart with the intended environment if needed. Termshark is a human viewer,
not the server's capture or analysis backend.

## 5. Filter languages and field paths are different

`filter_expression` uses normalized/Scapy fields. `display_filter` uses
Wireshark syntax and requires tshark. They are not interchangeable.

| Intent | Normalized expression | Wireshark expression |
| --- | --- | --- |
| VLAN 591 | `vlan_ids == 591` | `vlan.id == 591` |
| IPv4 TCP destination port | `ipv4.tcp.destination_port == 43099` | `tcp.dstport == 43099` |
| MAC address | `source_mac == "02:00:00:00:ab:01"` | `eth.src == 02:00:00:00:ab:01` |

Missing normalized fields do not match; a syntactically valid but incorrect
field path can return zero records. Quote MAC strings in normalized expressions.
Use `describe_filters` and inspect decoded fields before making absence claims.

## 6. Capture quality and analysis bounds

These are supported limits, not promises of unlimited or lossless operation:

- Kernel timestamps are software receive timestamps, not hardware wire timing.
- Packet-socket statistics describe that socket's observation, not every frame
  on the wire. Promiscuous membership does not certify hardware filtering.
- Low-rate byte-for-byte tests do not certify lossless gigabit capture.
- Frame/byte/time limits and truncation must be checked. A `frame_limit` stop
  correctly reports `capture_complete: false`.
- Retained packets can be a filtered subset of observed traffic; compare exact
  test identifiers and the common observation window, not total counts alone.
- DUT and host clocks need not be synchronized; cross-host timestamp differences
  are not automatically network latency.
- Replay pacing is bounded software scheduling, not precision hardware timing.
- File scans, pages and tshark queries are bounded. Inspect `scan_reason`,
  `scan_truncated`, `next_index` and query scope before claiming full-file coverage.
- Paging rescans prefixes and can hit the scan deadline for distant positions.
- Conversation IDs group endpoint pairs/VLAN/interface; reused TCP tuples are not
  necessarily separate connection incarnations.
- Stream inspection preserves bounded sequence evidence, gaps and overlaps. It
  is not complete TCP reassembly, IP defragmentation or TLS decryption.
- Preview/payload-display truncation differs from raw capture truncation; check
  the relevant fields rather than conflating them.
- Mixed-link capture analysis is supported where described, but replay requires
  Ethernet link types.

## 7. Capture-file fidelity and provenance

The current receiver reconstructs stripped outer VLAN headers from Linux
`PACKET_AUXDATA` before decoding, filtering and saving. VLAN 0, PCP/DEI and the
reported TPID are preserved; an existing inner tag does not suppress restoration
of a stripped outer tag.

Live results expose `vlan_reconstructed`; pcapng comments retain reconstruction
and timestamp provenance. Classic pcap retains restored bytes but not those
comments. Pcapng output regenerates interface IDs and uses microsecond timestamp
resolution; it is not a byte-for-byte reproduction of original sections,
interface descriptions or interface-statistics blocks. Unknown timestamps are
not silently invented.

Physical validation covered naturally occurring tagged traffic; unit coverage
for VLAN 0/PCP/DEI/QinQ restoration is not a substitute for a complete physical
receive-side matrix.

## 8. Privilege and platform boundaries

Live operations currently use Linux `AF_PACKET`; there is no Windows-native
Npcap live backend. Offline construction and analysis remain available without
live-capture privileges.

Use a dedicated capability-bearing interpreter as documented. Do not grant
capabilities to a shared Python installation merely to silence a warning. File
system support, interpreter replacement and mounts can affect capabilities;
verify with `setup-capabilities.sh --check`, not file metadata alone.

## Corrected historical issues

These are not known-open defects in the current source:

- Stripped receive VLAN headers: `PACKET_AUXDATA` restoration added and validated
  against standalone tshark exact frame bytes.
- Cross-interface queued traffic: bounded pre-bind drain and interface checks.
- Replies missed between transmissions: interleaved send/receive collection.
- Replay pacing: per-frame scheduling corrected; precision timing not promised.
- Ethernet padding interpreted as IP/UDP application payload: length boundaries
  respected.
- Pcapng comment encoding: correct list-of-encoded-comments representation.
- Negative live loopback DNS test: scope to test ARP replies, require received
  traffic, then separately evaluate the negative expectation. Three subsequent
  full-suite runs passed; the historical failure's exact traffic cause was not
  proven.

## Reporting a new issue

Include version/commit, platform/kernel, interface and driver, backend availability,
exact tool parameters, quality/scope fields, expected versus observed behavior,
and independent evidence where possible. Keep credentials and sensitive captures
out of the repository. Distinguish socket-send success, peer observation,
physical-wire delivery, decoder output and capture completeness.
