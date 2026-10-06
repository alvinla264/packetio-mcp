# PacketIO

**PacketIO** is one MCP server for **Ethernet packet generation, capture and evidence-based
packet analysis on real interfaces**.

Use arbitrary raw bytes for unusual protocols or `build_protocol_packet` for
allowlisted Ethernet/VLAN/QinQ/ARP/IP/UDP/TCP/ICMP layers with automatic lengths
and checksums. Bounded capture pages, selected fields, summaries and optional
Wireshark queries help an AI retrieve evidence without dumping entire captures.
No arbitrary Python expressions or shell commands are accepted by these tools.

The MCP server identifies itself as `PacketIO`. The distribution/command
`pktgen-mcp` and Python module `pktgen_mcp` remain unchanged for launcher
compatibility.

See [Known issues and operational limits](KNOWN_ISSUES.md) for unresolved receive
limitations, client deadlines, backend dependencies and corrected historical
issues. The [Linux USB receive-filtering note](docs/linux-usb-receive-filtering.md)
explains the alternate-MAC reception investigation and candidate driver remedies.

## Quickstart

**Recommended setup:** Linux (native or WSL 2), a **dedicated USB Ethernet
adapter/NIC** connected to an isolated device-under-test link, and **tshark plus
termshark** installed. For WSL, pass the USB NIC into Linux with `usbipd-win`;
merely plugging it into Windows still leaves it on the Windows networking path.
See [Windows laptops and WSL 2](#windows-laptops-and-wsl-2) for attachment steps.
Keep Wi-Fi/VPN or another adapter for normal connectivity.

### 1. Install locally

From a checkout of this repository (Python 3.10+ and `uv` required):

```sh
cd /path/to/pktgen-mcp
uv venv
uv pip install -e .
```

Keep the server running as your normal user rather than as root. On Linux/WSL, keep the checkout on a Linux
filesystem that supports capabilities (for example, under your WSL home directory,
not a Windows-mounted directory). See [Privileges](#privileges).

Install the recommended analysis utilities using your distribution's package
manager. For example, on Debian/Ubuntu where the packages are available:

```sh
sudo apt update
sudo apt install tshark termshark libcap2-bin
```

`libcap2-bin` provides `setcap`/`getcap`. After those utilities are available,
configure the dedicated interpreter:

```sh
./setup-capabilities.sh
./setup-capabilities.sh --check
```

Run the setup script as your normal user; it requests administrative permission
for the capability operation. Tshark and termshark are optional, not Python
package dependencies. No broad capture privileges or root execution are needed
for reading saved files.

### 2. Prepare the test NIC

After attaching the USB NIC to Linux/WSL, find its actual interface name:

```sh
ip -br link
sudo ip link set dev <test-interface> up
ip -br link show dev <test-interface>
```

Check link/carrier and connect the cable to the DUT. No IP address, DHCP or new
default route is required for raw Ethernet tests. Do not assume `eth0` is the
USB adapter, and do not change the normal Wi-Fi/VPN interface.

### 3. Connect your MCP client

Use the absolute dedicated interpreter path in the
[MCP client configuration](#mcp-client-configuration), then reload the server.
For a manual stdio launch:

```sh
.venv/bin/python3-capped -m pktgen_mcp.server
```

This starts an MCP server, not an interactive packet CLI. Ensure `tshark` is on
**the server process's PATH**, not only in another shell. Call
`describe_capabilities()` to confirm `tshark_available`; Scapy fallback works
without it, but Wireshark queries require it.

### 4. Run a small test and inspect evidence

Ask your AI client to:

1. Call `describe_capabilities()` and `list_available_interfaces()`.
2. Select the dedicated test interface and explicitly supply the intended MACs.
3. Build a frame with `build_packet`/`build_protocol_packet`; inspect it before
   sending. Use matching Ethernet and ARP sender MACs for ordinary ARP tests.
4. Run `run_packet_test` with a short observation window, bounded assertions and
   `save_as="first-test.pcapng"`. See the
   [test-sequence example](#essential-investigation-and-testing-tools).
5. Check the verdict **and** capture quality, then use `read_capture_file`,
   `analyse_capture`, `inspect_capture_page` or `query_capture` to inspect evidence.
6. For physical-delivery verification, independently capture on the DUT through
   serial or another approved observation path. Socket success is not proof that
   a packet reached the cable or DUT.

For a human review of the saved file:

```sh
termshark -r "$HOME/.local/state/pktgen-mcp/captures/first-test.pcapng"
```

The default capture directory is `~/.local/state/pktgen-mcp/captures`; deployments can override it with
`PKTGEN_CAPTURE_DIR`. Captures may contain sensitive traffic: keep them local,
avoid unrelated interfaces, and do not commit them.

### Recommended: tshark and termshark

- **tshark:** Wireshark's command-line analyzer, used by the MCP for optional
  dissection, display-filter queries and selected diagnostics.
- **[termshark](https://termshark.io/):** a terminal UI using tshark, recommended
  for independently reviewing saved captures. It is a human-facing companion,
  **not** an MCP dependency or a substitute for installing tshark.

The MCP remains one AI-facing server; termshark is optional tooling alongside it.

## Install and run

Runtime dependencies are FastMCP and Scapy, installed automatically with the
Python package. No tshark executable is required; if available on PATH it is
used for optional offline pcap analysis with automatic Scapy fallback. Scapy supplies pcap/pcapng
file reading/writing and bounded protocol dissection. Ethernet construction,
live AF_PACKET I/O, normalized compatibility fields, filters and summaries
remain implemented by this server.

Via `uvx` (no clone needed, once published):

```sh
uvx --from git+https://github.com/<you>/pktgen-mcp pktgen-mcp
```

Locally with `uv`:

```sh
uv run pktgen-mcp
```

With the bundled nix flake:

```sh
nix run .
```

### Privileges

Raw `AF_PACKET` sockets require `CAP_NET_RAW`. Everything else in the server
(frame building, decoding, filtering, capture file handling, summaries) is pure
computation and needs no privileges.

Use a capability on an access-restricted dedicated interpreter.

The server runs as your normal user. No password prompt, no root:

```sh
./setup-capabilities.sh          # configure
./setup-capabilities.sh --check  # verify
./setup-capabilities.sh --remove # undo
```

The script copies the interpreter behind the venv to
`.venv/bin/python3-capped` and applies `cap_net_raw+ep` to that copy.

**Why a copy and not the venv interpreter?** `.venv/bin/python` is normally a
symlink to the system Python, and `setcap` follows symlinks. Setting the
capability there would grant raw-socket access to every invocation of that
interpreter for every user on the machine. The copy avoids modifying shared
Python and is installed mode 0700. **Any Python code run with this copy obtains
CAP_NET_RAW**; it is not restricted to MCP tools or a single interface. Protect
the checkout, environment and executable from other users. Run setup as your
normal user; only the capability-setting command inside it invokes sudo.

**Re-run the script after the backing Python is upgraded.** The copied
executable is not automatically replaced by distribution updates.

**The server warns on startup if the capability is missing.** It keeps running
regardless, because building, decoding, filtering and capture file handling all
work unprivileged; only sending and live capture fail. The warning goes to
stderr, never stdout, since stdout carries the JSON-RPC stream, and it ends with
a complete command that can be pasted from any directory:

```
pktgen-mcp: raw packet sockets are unavailable (CAP_NET_RAW is not available to this interpreter).
pktgen-mcp: sending and live capture will fail. Available without privileges: build_packet,
decode_packet, read_capture_file, summarise_capture_file, list_capture_files, describe_*.
pktgen-mcp: grant CAP_NET_RAW with:
pktgen-mcp:     /absolute/path/to/pktgen-mcp/setup-capabilities.sh
pktgen-mcp: then restart this MCP server. This is a one-time step per machine, and is needed
again only if the virtual environment is rebuilt or the system Python is upgraded.
```

Tool calls that need the capability return the same remedy, so a failure is
actionable whichever path the caller hits first.

**Capabilities do not survive some filesystems.** If the venv lives on a mount
with `nosuid`, or on a filesystem that does not store extended attributes, the
capability is ignored. `--check` exercises a real socket to catch this rather
than trusting `getcap` output.

**Do not run the server, setup script or Python test suite as root.** The
server parses untrusted packet bytes and invokes optional third-party
dissectors. Do not grant capabilities to shared/system Python or grant a
passwordless-sudo rule for a general interpreter. See [SECURITY.md](SECURITY.md)
for the deployment trust boundary and publication checks.

### Running from a local path with uvx

`uvx --from <local-path>` keys its cached build on the package name and version,
not on the contents of the directory. When the source changes but the version
does not, uvx can reuse a stale build and serve an older set of tools. Bump
`version` in `pyproject.toml` after changing the source, or clear the cache:

```sh
uv cache clean pktgen-mcp
```

## MCP client configuration

Assuming the dedicated-interpreter setup above, so the server runs as your
own user:

```json
{
  "mcpServers": {
    "pktgen": {
      "type": "stdio",
      "command": "/absolute/path/to/pktgen-mcp/.venv/bin/python3-capped",
      "args": ["-m", "pktgen_mcp.server"],
      "cwd": "/absolute/path/to/pktgen-mcp",
      "exposure": "direct"
    }
  }
}
```

`cwd` matters: it is what makes the `pktgen_mcp` package importable without an
install step. `command` must be absolute, and the capability is on that exact
file.

Keep this transport local and accessible only to trusted clients. Do not
publish an unauthenticated HTTP/SSE endpoint for raw packet tools.

## How frames are built and sent

The MCP client supplies structured fields or complete frame bytes. The frame builder and sender
use Python's standard library; Scapy is used for capture-file I/O, not for
sending. No external packet-generation CLI is required.

1. `server.py` accepts the tool arguments and calls the frame builder.
2. `packets.py` converts MAC addresses and payload hex to bytes and packs fields
   in network byte order. The `ethernet` builder assembles:

   ```text
   destination MAC | source MAC | optional VLAN tags | EtherType | payload | padding
   ```

   An 802.1Q tag uses TPID `0x8100`. QinQ uses outer TPID `0x88a8` followed by
   inner TPID `0x8100`. Each tag carries the VLAN ID, PCP and DEI.
   The `raw` builder instead accepts the complete Ethernet frame as `frame_hex`.
3. `capture.py` opens a Linux raw packet socket, binds it to the selected
   interface and sends the frame bytes. The essential operations are:

   ```python
   sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
   sock.bind((interface, 0))
   sock.send(frame_bytes)
   ```

`0x0003` is `ETH_P_ALL`, used to receive Ethernet protocol types. The supplied
interface determines the transmission path: ordinary IP routing, DHCP and a
configured interface IP address are not required for Layer-2 tests.

Higher-level headers and checksums are the caller's responsibility. For example,
ARP is supplied as payload bytes with EtherType `0x0806`; the builder does not
construct ARP automatically. Short frames are padded to 60 bytes by default,
excluding the FCS normally added by Ethernet hardware. This is not a facility
for controlling preambles or deliberately corrupting the FCS.

A successful socket send means the kernel accepted the bytes, **not** that a
physical peer received them. Verify delivery with a peer capture or a response.

## Windows laptops and WSL 2

### Mirrored interfaces are not direct NIC ownership

WSL's default NAT networking and its mirrored networking are different modes.
Do not diagnose a mirrored-mode failure as a NAT problem without evidence.
Mirrored mode presents virtual interfaces corresponding to Windows adapters;
those interfaces can use `hv_netvsc` even when their names and MAC addresses
resemble a physical adapter.

```text
MCP in WSL -> virtual NIC -> Windows/Hyper-V networking -> physical NIC -> DUT
```

Normal IP connectivity does not establish transparent handling of arbitrary
EtherTypes, spoofed MAC addresses or VLAN stacks. There is a matching raw
`AF_PACKET` failure report in [WSL issue #11446](https://github.com/microsoft/WSL/issues/11446),
but it was automatically closed for lack of feedback, not with a documented
root-cause determination. It is not proof that all mirrored-mode injection fails.
See [Microsoft's networking documentation](https://learn.microsoft.com/en-us/windows/wsl/networking)
for the distinction between NAT and mirrored modes.

### Why a dedicated USB NIC is recommended

For **arbitrary Ethernet testing**, prefer a dedicated USB Ethernet adapter/NIC
owned by Linux. This is a recommendation based on physical validation, not a
claim that every built-in NIC or every WSL installation fails.

A later controlled test of a linked built-in Ethernet adapter through mirrored
WSL used 20 cases/two transmissions each, with simultaneous Windows physical-NIC
capture and independent DUT ingress capture. Results were:

| Traffic generated in WSL | Observed at the DUT |
| --- | --- |
| Valid ARP and IPv4 ICMP/UDP using the actual interface MAC | Yes |
| Custom EtherTypes, broadcast or unicast | No matching test frames observed |
| VLAN/QinQ carrying custom traffic or ARP | No matching test frames observed |
| ARP/ICMP/UDP using a spoofed source MAC | No matching test frames observed |
| Custom frames across several sizes up to a 1514-byte frame | No matching test frames observed |

All socket sends reported success; the missing test frames were also absent from
Windows' physical-adapter capture. This implicates the host-side path but does
**not** identify an exact dropping component. A broad WSL capture had drops and
reached its frame limit, so its missing packets were not used as failure proof.
The DUT capture reported zero kernel drops. Results apply to the tested setup,
not a universal WSL protocol allowlist or hardware limitation.

Microsoft documents [source-MAC policy](https://learn.microsoft.com/en-us/powershell/module/hyper-v/set-vmnetworkadapter)
and [security/VLAN enforcement in Hyper-V's packet path](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/packet-flow-through-the-extensible-switch-data-path).
These are plausible mechanisms, not proof of the actual policy on this mirrored
endpoint. The older [WSL MAC-spoofing report](https://github.com/microsoft/WSL/issues/8602)
provides additional symptom evidence, not a guaranteed configuration fix.

The USB-passthrough path was separately verified for custom EtherTypes,
VLAN/QinQ and spoofed-source transmission. Spoofed-MAC **reply reception** remains
unresolved; do not equate successful spoofed transmission with receive support.

On native Linux, a built-in NIC with a suitable driver can also be a valid test
interface; the WSL virtualization concern does not automatically apply. If using
mirrored WSL, validate each required operation independently. Do not disable
VPN/security filters, firewalls or change virtual switches merely to try to
make raw frames work. Windows-native Npcap injection through the same adapter is
a useful diagnostic control, but is not a backend implemented by this server.

### Tested path: pass a dedicated USB Ethernet device into WSL

A USB Ethernet dongle or a hub containing a USB Ethernet controller can be
attached to WSL using `usbipd-win`. A hub itself is not required. Linux then uses
a USB NIC driver instead of the mirrored virtual Ethernet path:

```text
MCP in WSL -> Linux USB NIC driver -> USB/IP -> USB Ethernet device -> DUT
```

Windows still transports the USB/IP connection, but the test Ethernet frames
are handled by the USB NIC rather than a mirrored network interface. This path
can coexist with mirrored networking and a separate Windows Wi-Fi/VPN
connection. While attached, the selected USB device is unavailable to Windows.
A PCI-connected built-in NIC cannot be attached using this USB mechanism.

#### Setup

Follow [Microsoft's USB passthrough instructions](https://learn.microsoft.com/en-us/windows/wsl/connect-usb)
to install `usbipd-win`. Check the actual adapter chipset/USB ID and availability
of its Linux driver before choosing an adapter; support varies by WSL kernel.
For example, an RTL8153 adapter was successfully bound to `r8153_ecm` in our
test even though the usual `r8152` driver was absent.

In Windows PowerShell:

```powershell
usbipd list

# Administrator prompt: initially share only the Ethernet device.
usbipd bind --busid <ethernet-busid>

# Normal prompt, with WSL running: attach it for use.
usbipd attach --wsl --busid <ethernet-busid>
```

Do not select unrelated hub functions such as storage or input devices.
In WSL, identify the newly attached interface:

```sh
lsusb
ip -br link
readlink -f /sys/class/net/<usb-interface>/device/driver
sudo ip link set dev <usb-interface> up
ip -br link show dev <usb-interface>
```

Use that interface in MCP calls. Names such as `enx<MAC>` are possible; do not
assume it will be `eth0`. `state UNKNOWN` alone is not a failure: check `UP`,
`LOWER_UP` and the carrier indication. No DHCP or default route is required for
raw Ethernet tests; leave the dedicated test interface separate from the normal
internet route.

Detach when finished:

```powershell
usbipd detach --busid <ethernet-busid>
```

Sharing is persistent, but attachment ends when the device is unplugged or WSL
restarts. See the [usbipd lifecycle documentation](https://github.com/dorssel/usbipd-win/wiki/WSL-support).
USB/IP overhead and NIC/driver behavior still require validation for the desired
traffic; this is not a line-rate or precision-timing guarantee.

### Distinguish host and DUT interface names

Interface names are local to each machine. In the tested topology:

```text
WSL <usb-interface> -> USB Ethernet -> cable -> DUT eth0 -> DUT br-lan
```

MCP sent on the **WSL USB interface**. A separate `tcpdump` controlled through
serial captured on **DUT eth0**. WSL's own `eth0` was not used for those tests.

### How to investigate a built-in NIC failure

Before concluding an external NIC is necessary:

1. Connect the DUT to the built-in port and verify physical link in Windows and
   WSL. Identify the correct mirrored interface by adapter/MAC, not just name.
2. Capture simultaneously on the Windows Ethernet adapter and the DUT's physical
   ingress port; use a separate host capture socket if observing local TX.
3. Send a valid ARP request using matching Ethernet and ARP sender MACs equal to
   the actual adapter MAC, followed by a uniquely marked untagged frame.
4. Compare observations, then test spoofing and VLANs separately. Host capture
   visibility alone is not proof of physical delivery.
5. If needed, compare Windows-native Npcap injection through the same NIC. That
   would require an additional backend; it is not implemented by this server.

## Tools

### Generation and send/receive

| Tool | Purpose |
| --- | --- |
| `list_available_interfaces` | Discover interfaces and their up/down state and MAC |
| `describe_builders` | Read the accepted builder arguments before formatting a frame |
| `build_packet` | Build a frame and return its bytes; never transmits |
| `send_packet` | Transmit a frame, no reply collection |
| `send_and_receive` | **Transmit and capture the reply** on the same interface |

### Analysis

| Tool | Purpose |
| --- | --- |
| `capture_packets` | Passively listen; optionally filter, summarise and save to a file |
| `decode_packet` | Decode a frame supplied as hex |
| `describe_decode_support` | List which protocols the decoder recognises |
| `describe_filters` | Read the filter expression language |
| `list_capture_files` | List capture files in the capture directory |
| `read_capture_file` | Read a capture file, optionally filtered |
| `summarise_capture_file` | Summarise a capture file without returning every frame |
| `replay_capture_file` | Re-send a capped number of frames with per-frame pacing |
| `describe_capabilities` | Discover backends, limits, formats and caveats |
| `build_protocol_packet` | Construct allowlisted protocol layers; never transmit implicitly |
| `inspect_capture_page` | Indexed pages with selected normalized/Scapy fields |
| `query_capture` | Wireshark display filter and selected fields; tshark required |
| `diagnose_capture` | Evidence for retransmissions, DNS failures, ARP or DHCP |
| `analyse_capture` | Streaming protocol counts and bounded conversation tracking |
| `inspect_stream` | Conversation timeline, UDP datagrams and TCP sequence ranges |
| `run_packet_test` | Declarative send/capture/assert sequence with saved evidence |

### Request/response

`send_and_receive` binds a raw socket to the interface, drains stale frames,
transmits the request, then reads captured frames until the deadline. The reply
window starts after the final send. A send/receive event loop collects replies
between transmissions, including during paced sequences. Socket buffers can still
overflow under load. Capture-quality results report socket drops, stop reason,
promiscuous-mode status and kernel software timestamp support. The raw receiver
enables Linux `PACKET_AUXDATA` and restores stripped outer VLAN headers before
decoding, filtering and saving packets. Live results expose `vlan_reconstructed`;
pcapng comments preserve that provenance. Restoration preserves VLAN 0, PCP/DEI,
and the reported TPID, including an outer tag with an inner QinQ tag still in
the packet bytes. Classic pcap retains the restored bytes but not provenance.
Frames are split into:

- `replies` — frames received from the peer
- `own_frames` — frames this host transmitted

so a reply is never confused with the request.

A promiscuous socket on a busy link also sees unrelated broadcast and multicast
traffic. Pass `reply_source_mac`, `reply_ether_type` or `reply_filter` to keep
only the plausible answer; `capture_packets` accepts the same narrowing via
`source_mac_filter`, `ether_type_filter` and `filter_expression`.

## Decode verbosity

Every capture-facing tool takes `decode`, one of:

- `none` — transport metadata and raw hex only
- `summary` — a compact identification line per frame (default for file reads)
- `full` — the complete decoded tree

Full decoded results include a `scapy` object with `backend`, `layer_names`,
`protocol` and `layers` (layer names with parsed fields). Summaries include
`layer_names`, and capture overviews include a `scapy_layers` histogram.
Existing normalized fields such as `arp.operation`, `ipv4.source_ip` and
`vlan_ids` remain unchanged for compatible filters and assertions. The existing
`protocol` label remains the compatibility label; `scapy.protocol` identifies
the innermost dissected layer excluding raw data and padding.

The Scapy tree is bounded to 16 layers, 64 fields per object, 16 list items,
4 levels of value nesting and 256 characters of text. Byte previews respect the
requested payload limit up to 256 bytes; clipped details are marked
`truncated`. Raw frame hex is retained in full/none modes, independently of
these tree bounds. Unknown payloads remain raw data. Malformed frames are
best-effort and dissection errors do not discard the original bytes.

Offline pcap dissection uses the capture's link type (including raw IP and Linux
cooked captures), rather than assuming Ethernet. Unknown link types report an
explicit error, and non-Ethernet captures cannot be replayed by the Ethernet
sender. Non-Ethernet results expose Scapy fields, not Ethernet compatibility
fields. Standard Scapy layer bindings are loaded; not all optional/contrib
protocols are automatically loaded. This integration does not implement TCP
stream reassembly or checksum/conformance certification.

Filters can additionally use `scapy.layer_names == GRE` or
`scapy.protocol == dns`; they remain this MCP's filter language, not Wireshark
display filters.

The decoder is a context compressor, not an oracle. It extracts the fields needed
to identify a frame so a large capture can be triaged without returning
everything. **Raw hex is always available**, so an unrecognised or proprietary
protocol is never a dead end — the bytes can simply be read directly.

Recognised protocols:

| Layer | Fields reported |
| --- | --- |
| Ethernet | source/destination MAC, VLAN tag stack, EtherType |
| ARP | operation, sender and target MAC/IP |
| IPv4 | addresses, TTL, protocol, fragmentation |
| IPv6 | addresses, hop limit, next header (extension headers walked) |
| TCP | ports, flags, sequence, acknowledgement, window |
| UDP | ports, length |
| ICMP / ICMPv6 | type, code, id, sequence, neighbour-discovery target |
| DHCP | message type, transaction id, client MAC, your IP, server id, lease, subnet, routers, hostname, requested IP |
| DNS | transaction id, flags, question name/type, first answer (follows compression pointers) |
| LLDP | chassis id, port id, TTL, system name, system description, capabilities |

Fields are omitted rather than guessed when a frame is malformed or truncated.

## Filter expressions

Filters match on decoded fields and combine with `and`, `or`, `not` and
parentheses. A missing field never matches, so a filter cannot be satisfied by a
frame that merely lacks the field it mentions.

```
protocol == dhcp
protocol == arp and arp.operation_name == reply
ipv4.tcp.destination_port == 443
ipv4.source_ip ~ '192.168.'
protocol in (dhcp, dns) and vlan_ids == 300
not protocol == arp
```

Operators are `==`, `!=`, `>`, `<`, `>=`, `<=`, `~` (case-insensitive
substring) and `in`. List-valued fields such as `vlan_ids` match when any member
satisfies the comparison. Call `describe_filters` for the full field list.

## Expectations

`send_and_receive` accepts an `expect` object so a caller can assert on the
outcome instead of reading frames back to judge them:

```
send_and_receive(
  interface="eth1",
  ether_type="0806",
  payload_hex="...",
  expect={
    "reply_count_at_least": 1,
    "filter": "protocol == arp and arp.operation_name == reply",
  },
)
```

The result carries an `expectation` block with `matched` and the detail of every
check. Expectations are evaluated against the raw reply bytes, so the chosen
`decode` verbosity cannot change whether an assertion passes.

## Optional tshark analysis

`read_capture_file` (summary/full modes) and `summarise_capture_file` automatically
look for `tshark` on the MCP server's `PATH`. If found, tshark is preferred for
additional offline dissection. If absent, failing, timing out, or exceeding the
analysis bounds, the tools return the existing Scapy/normalized results with an
explicit fallback reason. Nothing is downloaded or installed automatically.
For an MCP running in WSL, install tshark **inside WSL** if you want this feature;
a Windows Wireshark installation alone is not automatically used.

Results expose `analysis_backend` (`tshark`, `scapy`, or `none` for raw-only
reads) and, when falling back, `analysis_fallback_reason`. Full-mode frames add
`tshark.layers` and `tshark.protocols`; summaries add only the protocol stack.
Standalone capture summaries include `tshark_protocol_stacks` when available.
Scapy trees and normalized fields remain for compatibility. Existing filters,
assertions and normalized overview counters continue to use the same schema:
this does not silently turn `filter_expression` into a Wireshark display filter.
Live capture and `decode_packet` continue using Scapy; optional tshark is used
only for offline capture-file inspection, not sending or replay.

The optional subprocess receives a temporary copy of the parsed capture prefix
before MCP filtering, keeping context within that prefix. Limits are 200 packets,
4 MiB of frame bytes, 10 seconds of runtime, and 8 MiB of combined subprocess
output. Output size is checked periodically (a fast writer may briefly overshoot
before termination). Captures beyond the input bounds fall back entirely to
Scapy, rather than silently analysing only a sample. Returned tshark JSON is
further bounded by field count, nesting, list length and string length.

The subprocess uses fixed argument lists without a shell, disables name
resolution with `-n`, and only reads the temporary capture with `-r`.
Offline analysis requires no elevated user privileges. Keep tshark updated;
capture files are untrusted parser input. Wireshark's dissectors may provide
richer fields and diagnostics, but bounded-prefix analysis is not a guarantee
of complete stream reconstruction or full-capture conformance analysis.

## Capture files

Capture-file I/O uses Scapy's `RawPcapWriter` and `RawPcapReader`, preserving raw
frame bytes without protocol dissection or packet rebuilding. Reads stream from
the file rather than loading its entire contents before parsing. Returned
records are still collected in memory, so use `max_records` when appropriate.

Captures are written in classic `.pcap` format, little-endian, with link type
`DLT_EN10MB`. Reading also accepts big-endian files, nanosecond timestamps and
other classic-pcap link types; Scapy dissection is selected by the file's link
type, with normalized compatibility fields available for Ethernet captures.
An incomplete final record is omitted. Pcapng reads preserve each packet's link
type, interface name and direction when present, plus timestamp resolution.
Mixed-link captures are decoded and summarized per packet; replay rejects them
rather than treating them as Ethernet. Ranged tshark queries support mixed links
using temporary pcapng input. Records expose section-scoped interface IDs and
bounded comments. Interface descriptions and available interface-statistics
blocks are reported as metadata.

Use `.pcapng` for live capture or test evidence to preserve name/direction metadata.
Pcapng output regenerates IDs and uses microsecond resolution; colliding names may
be suffixed. Unknown timestamps are rejected for writing rather than invented.
Output does not reproduce original section layout/descriptions/statistics.

Input files are limited to 1 GiB, scans to 1,000,000 packet positions/15 seconds,
parser block allocations to 4 MiB, and retained records to 32 MiB. Individual raw
packet reads are limited to 262144 bytes. `analyse_capture` streams counters and
tracks at most 2048 flows without retaining frames. Existing summaries retain a
bounded prefix. Results report scope/truncation; never treat a partial scan as
complete. Very large/slow scans can reach the time limit before a requested page.

Files are confined to one directory, set by `PKTGEN_CAPTURE_DIR` and defaulting
to `~/.local/state/pktgen-mcp/captures`. The directory must be owned by the
server user and mode 0700. New captures and report sidecars are mode 0600;
existing outputs are never overwritten. Symlinks and special-file inputs are
rejected through descriptor-based opens. Tools accept relative filenames, not
absolute paths or parent traversal. Existing deployments using a shared or
0755 capture directory must explicitly choose a private directory; the server
does not silently change existing permissions or move evidence.

```
list_capture_files()
read_capture_file("run1.pcap", filter_expression="protocol == dhcp")
summarise_capture_file("run1.pcap")
replay_capture_file("run1.pcap", "eth1", max_frames=100, rate_pps=10)
```

Replay spaces each selected frame by at least `1/rate_pps` using ordinary Python
scheduling. This is a rate limit, not precision hardware timing. Keep tests small
and on isolated links. The original multi-frame pacing defect has been fixed.

## Summaries

A summary reports which protocols, hosts, conversations, VLANs and addresses
were seen, so a caller can decide which frames are worth reading:

- protocol histogram and EtherType counts
- VLANs observed
- top conversations (direction independent, IP or MAC pairs)
- top talkers and transport services (keyed on the lower port)
- DHCP servers and offered addresses
- DNS questions
- ARP requesters and responders, separated

## Examples

ARP request for `192.168.1.1` from `192.168.1.10` and read the reply:

```
send_and_receive(
  interface="eth1",
  builder="ethernet",
  destination_mac="ff:ff:ff:ff:ff:ff",
  source_mac="02:11:22:33:44:55",
  ether_type="0806",
  payload_hex="00 01 08 00 06 04 00 01 02 11 22 33 44 55 c0 a8 01 0a 00 00 00 00 00 00 c0 a8 01 01",
  timeout=2.0,
  reply_ether_type="0806",
)
```

The reply appears under `replies` with `arp.operation = 2` and the responder's
MAC in `source_mac`.

An illustrative gateway request, filtered to one responder so unrelated
broadcast traffic is excluded. These documentation IP addresses and locally
administered MACs are placeholders; replace them with authorized test endpoints:

```python
send_and_receive(
  interface="<test-interface>",
  ether_type="0806",
  destination_mac="ff:ff:ff:ff:ff:ff",
  source_mac="02:00:00:00:00:01",
  payload_hex=(
    "00 01 08 00 06 04 00 01 "       # Ethernet/IPv4 ARP request
    "02 00 00 00 00 01 "             # sender MAC
    "c0 00 02 02 "                   # sender IP: 192.0.2.2
    "00 00 00 00 00 00 "             # target MAC unknown
    "c0 00 02 01"                    # target IP: 192.0.2.1
  ),
  timeout=3.0,
  reply_source_mac="02:00:00:00:00:02",
  reply_ether_type="0806",
)
```

A corresponding ARP response would report `operation=2`. Real test-network
addresses and hardware identifiers are deliberately omitted from this example.

A single-tagged frame:

```
send_packet(
  interface="eth1",
  ether_type="88b5",
  vlan_mode="802.1q",
  vlan_id=200,
  pcp=5,
  payload_hex="de ad be ef",
)
```

An exact frame, including one captured from a peer:

```
send_and_receive(interface="eth1", builder="raw", frame_hex="ff ff ff ff ff ff 02 00 00 00 00 01 88 b5 de ad be ef")
```

## Notes

- Short frames are padded to the 60-byte Ethernet minimum by default. The FCS is
  added by hardware and never appears in the hex.
- `capture_packets` requests promiscuous mode; interfaces such as `lo` may reject
  the membership, which is not fatal.
- Send on an interface that is up. `list_available_interfaces` reports the flags.
- Only one process should hold a promiscuous capture on an interface when precise
  framing matters; concurrent capture can interleave unrelated traffic.
- On a busy link, always constrain the capture with `reply_source_mac`,
  `reply_ether_type` or an increase of `timeout` rather than assuming every
  captured frame is a reply.

## Live validation results and known limitations

A bounded test against a physical device using USB Ethernet passthrough verified:

| Test | Evidence |
| --- | --- |
| Untagged custom EtherType `0x88b5` | 2 frames delivered exactly |
| Spoofed source MAC | 2 frames delivered exactly |
| VLAN 123, PCP 5, DEI 1 | 2 frames delivered exactly |
| QinQ outer VLAN 456 / inner VLAN 123, with PCP/DEI | 2 frames delivered exactly |
| Explicit raw builder | 61-byte frame delivered exactly |
| MTU-sized payload | 1514-byte Ethernet frame delivered exactly |
| ARP with the adapter's actual MAC | 3 requests, 3 replies; expectations passed |
| Capture, pcap read, filtering and summary | Passed with captured ARP replies and imported DUT pcap |

All ten transmission-matrix frames in the DUT physical-interface capture were
compared byte-for-byte against reconstructed expectations and matched. This
establishes ingress delivery, not DUT VLAN forwarding policy or conformance.
Ordinary `send_packet` repetitions at 0.2-second intervals showed approximately
that spacing on the DUT. A payload exceeding the interface MTU was rejected;
jumbo-frame support was not established.

The same testing exposed limitations despite the automated suite passing:

- **Replay pacing (fixed):** the original implementation bunched frames. Every
  frame is now spaced, with a regression covering multi-frame repetitions.
- **Passive capture isolation (hardened):** pre-bind traffic is drained and receive
  explicitly rejects other-interface addresses. A regression injects a wrong-interface
  record. This addresses the observed leakage without claiming its original root cause
  was conclusively isolated.
- **Spoofed-MAC return reception:** the DUT captured spoofed ARP requests and
  outgoing replies addressed to the spoofed MAC, but WSL/MCP captured none even
  with promiscuous capture requested. Spoofed transmission passed; receive-side
  driver/hardware/path behavior remains unresolved.
- **Capture timing (improved):** Linux kernel software receive timestamps are
  requested, with an explicit userspace fallback. These are not hardware/wire
  timestamps. Receiving is interleaved with sending rather than deferred to the
  end of a sequence.

The physical ingress capture reported no kernel drops. The DUT bridge capture
also contained all ten frames but reported four interface drops; do not infer
universally lossless capture. No flooding, malformed-frame fuzzing, FCS control,
throughput certification or precision-timing certification was performed.

The initial automated capped-interpreter suite reported **227 passed, 2 skipped**.
Its live tests use loopback, so passing it does not establish physical NIC,
virtual networking or promiscuous reception correctness.

After adding the AI workflows, a fresh stdio MCP server under
`nix-shell -p wireshark-cli` exposed 18 tools and passed paging, selected-field
queries, QinQ Wireshark filtering, checksum-aware construction and live ARP.
Independent DUT serial-console tcpdump observed three replay frames at 2 pps,
with intervals of **0.500337 s** and **0.499943 s** (normal wire/scheduling jitter),
and no kernel drops in that five-packet ARP/replay capture. A separate USB capture
while injecting two loopback frames returned no wrong-interface frames. These
are bounded checks, not throughput or precision-timing certification.

## AI analysis workflow

1. Call `describe_capabilities` and `list_available_interfaces` before testing.
2. Build bytes with `build_packet` or `build_protocol_packet`, then explicitly send.
3. Capture on the intended interface and save as `.pcap`.
4. Use `summarise_capture_file` for orientation and `inspect_capture_page` for
   precise evidence (zero-based `packet_index`). `read_capture_file` also supports
   `start_index`; pages contain at most 200 packets and filtering occurs after paging.
   An empty filtered page may still have `next_index`. Scans currently cannot start
   beyond packet position 999,999; file/time/block limits still apply.
5. For Wireshark semantics, use `query_capture` with `display_filter` and 1–16
   field names. Example: `eth.type == 0x88a8` selects QinQ Ethernet frames;
   Wireshark's outer service tag is not necessarily represented as `vlan.id`.
   Queries accept `start_index` and scan a selected range of at most 200 packets
   (4 MiB), with 10-second and 8-MiB subprocess-output limits. Each row includes
   original `source_packet_index` and `source_frame_number`. Native tshark
   `frame.number` filters/fields refer to the temporary range, not the original file.
6. Use `diagnose_capture` with `tcp_retransmissions`, `dns_failures`,
   `arp_requests`, `dhcp_exchanges` (tshark required), or `unanswered_arp`
   (bounded normalized request/reply correlation, no tshark needed).

Neither a zero-match query nor an ARP request without an observed reply proves a
DUT defect. Capture boundaries, truncation, packet loss and NIC behavior matter.
TCP diagnostics can depend on earlier traffic absent from the selected prefix.
`inspect_stream` provides bounded TCP sequence ranges/UDP datagrams, not a
full-capture TCP reassembly or application-decryption contract.

To make tshark available to a **new** server process without changing the machine:

```sh
nix-shell -p wireshark-cli --run '.venv/bin/python3-capped -m pktgen_mcp.server'
```

Changing a parent shell does not change the PATH of an already-running MCP server.
Reload the server after changing its launch configuration.

## Essential investigation and testing tools

`analyse_capture` streams protocol counts and a bounded conversation list. Each
conversation includes a stable endpoint/VLAN/interface ID and representative
packet indexes. IDs do not separate multiple TCP connections reusing the same
tuple. `inspect_stream` returns a timeline, TCP flags and sequence-space payload
ranges, gaps, overlaps and conflicts. First-seen bytes win conflicts; gaps are
not silently filled. Limits: 200 matching packets, 64 KiB retained payload per
direction and 16 ranges/datagrams. Fragmented traffic is excluded from flow
tracking; no IP defragmentation, full TCP state machine or TLS decryption.

`run_packet_test` validates all steps/assertions before sending. Steps contain
`frame_hex` OR `layers`, with optional `payload_hex` and `delay_before`. Assertions
contain a normalized `filter`, `count_at_least`/`count_at_most`, and optionally
`after_send_index`/`within_seconds`. Only incoming frames satisfy assertions.
The runner reports `passed`, `failed` or `inconclusive` separately from execution
`ok`. Known drops/capture limits make the result inconclusive. Unknown drop
counters produce a warning. Lack of a response is only a bounded observation.

Example (use an isolated test interface and explicit destination):

```python
run_packet_test(
    interface="test0",
    steps=[{"layers": [
        {"protocol": "ethernet", "fields": {
            "src": "02:00:00:00:00:01", "dst": "ff:ff:ff:ff:ff:ff"}},
        {"protocol": "arp", "fields": {
            "op": 1, "hwsrc": "02:00:00:00:00:01",
            "hwdst": "00:00:00:00:00:00", "psrc": "0.0.0.0", "pdst": "192.0.2.2"}}
    ]}],
    assertions=[{"filter": "protocol == arp and arp.operation == 2",
                 "count_at_least": 1, "after_send_index": 0, "within_seconds": 1}],
    timeout=2, save_as="arp-test.pcapng"
)
```

Evidence includes indexed frames, transmissions, capture quality and a JSON
report sidecar. Limits: 100 steps, 32 assertions, 90 seconds, 5000 captured
frames/32 MiB. Payloads may contain sensitive data; protect captures/reports and
never commit them. Capture results are bounded, but callers should choose small
`max_frames`/summary output to avoid large model-context responses.

Structured construction additionally supports DNS questions, BOOTP/DHCP,
ICMPv6 echo and neighbor discovery, selected TCP options and explicit checksum/
length overrides for negative tests. `describe_capabilities` lists fields.
DNS accepts `qname`/`qtype`; DHCP accepts `message_type` and selected options;
TCP `options` is a list of `{name, value}` objects (MSS, WScale, Timestamp,
SAckOK, NOP, EOL). Numeric IP addresses and explicit MACs prevent unintended
network resolution. Raw frames remain available for unsupported protocols.

The essential-feature stdio E2E test exercised 21 tools under real tshark,
mixed-link/ranged queries, stream inspection and a three-request physical ARP
test. Host assertions passed with kernel software timestamps and zero socket
drops; pcapng evidence was read back successfully. Independent serial evidence
for that run was not retrieved because the serial adapter disappeared.

## Tests

```sh
# offline only, no privileges needed
.venv/bin/python scripts/test_offline.py

# everything, including live interface round-trips, with no sudo
.venv/bin/python3-capped -m pytest tests -q

# or run the full suite as root
# Never run the test suite as root.
```

Live tests exercise send/receive on `lo`. They are skipped automatically unless
the process can actually open a raw socket, so the suite passes both
unprivileged and with the capability configured. The check probes a real socket
rather than inspecting the user id, which is why the capped interpreter runs the
live tests without being root.
