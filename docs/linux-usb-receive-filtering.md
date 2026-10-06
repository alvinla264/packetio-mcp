# Linux USB Ethernet receive filtering

## Scope

This note explains an alternate-destination unicast receive failure observed on
one RTL8153 adapter in CDC Ethernet/ECM mode under USB/IP. It is not a universal
claim about USB adapters, Linux, Windows or WSL. No private device credentials,
addresses or capture contents are included.

## Evidence and confidence

Observed behavior:

1. Spoofed-source requests reached the peer.
2. Peer-side capture recorded replies addressed to the alternate MAC.
3. Concurrent standalone tshark and the MCP receiver both missed those replies.
4. Broadcast and original-MAC reception worked.
5. Changing Linux's logical interface MAC did not restore reception.
6. Restoring the original MAC restored normal request/reply behavior.

The leading explanation is a missing device-filter update in the active
`r8153_ecm` driver, together with a software-only inherited MAC setter. Source
inspection and the installed module's callback references corroborated this
mechanism. It has **not** been validated by a patched-driver test or a USB
control/bulk trace. Peer outgoing capture alone does not prove physical-wire
arrival at the adapter.

## Environment facts

The examined kernel was `6.18.33.2-microsoft-standard-WSL2`:

```text
# CONFIG_USB_RTL8152 is not set
CONFIG_USB_NET_CDCETHER=m
CONFIG_USB_RTL8153_ECM=m
```

The device used USB configuration 2 (CDC ECM) and `r8153_ecm`; it also advertised
a vendor-specific configuration 1. The `r8152` module was absent. These facts
must be rechecked on another host or after a kernel update.

## Why promiscuous membership is insufficient

The [WSL `r8153_ecm` source][ecm] defines `r8153_info` without a `set_rx_mode`
callback. Its bind routine calls `usbnet_cdc_bind`, which initializes filtering
through CDC helpers, but binding to those helpers does not inherit all callbacks
from the separate generic CDC Ethernet driver.

The [USB networking core][usbnet] invokes the minidriver's receive-mode callback
only when supplied. The [CDC filter helper][cdc] sends
`SET_ETHERNET_PACKET_FILTER` to the USB device and includes the promiscuous bit
when Linux's `IFF_PROMISC` flag is set. The generic CDC Ethernet driver explicitly
registers `.set_rx_mode = usbnet_cdc_update_filter`; the examined ECM driver does
not.

Consequently, Linux can accept `PACKET_MR_PROMISC`, log an interface transition,
and expose promiscuous state while the adapter still filters incoming unicast
against its original address. Packet-socket drop counters cannot describe
frames never delivered to that socket.

## Why a logical MAC change did not repair reception

The [USB networking operations][usbnet-mac] use `eth_mac_addr` by default.
The [Ethernet helper's documentation][eth] explicitly states:

> This doesn't change hardware matching, so needs to be overridden for most real devices.

Updating Linux's address is therefore not proof of programming the adapter's
hardware matching registers. The examined ECM driver does not install a
hardware-aware override. The [Realtek vendor driver][vendor] has a distinct
`rtl8152_set_mac_address` operation; that driver was not available in the examined
kernel.

## Candidate remedies

### Wire the ECM receive-mode callback

A minimal driver candidate is:

```c
.set_rx_mode = usbnet_cdc_update_filter,
```

in `r8153_info`. This connects mode changes to the CDC helper; it does not itself
provide hardware MAC programming or prove that firmware honors the request.
Build against the exact running kernel and verify device behavior before calling
it a fix. Module replacement, unloading, USB configuration changes and kernel
updates require explicit operator approval and a recovery plan.

### Use the supported vendor driver

A kernel with `CONFIG_USB_RTL8152` enabled and correct vendor-mode driver binding
is another candidate. Do not force an incompatible interface onto a driver or
assume a simple `modprobe` works when the module is absent. Changing USB
configuration may disconnect the device and change interface names.

### Use an independently qualified adapter

An alternate adapter or native-Linux control run can separate driver/USB/IP
behavior from peer delivery without changing the MCP's capture architecture.
For current exchanges requiring unicast replies, use the actual adapter MAC.

## Validation plan

Capture USB transactions around receive-mode activation and a bounded
alternate-MAC exchange:

1. Is CDC `SET_ETHERNET_PACKET_FILTER` (`bRequest = 0x43`) sent with the
   promiscuous bit enabled?
2. Does the device accept it?
3. Does USB bulk-IN contain the missing reply?
4. If USB receives it, does the Linux interface and then the packet socket see it?

Interpretation:

- Missing command supports the absent-callback mechanism.
- Accepted command with no incoming frame leaves firmware filtering and peer/wire
  delivery to investigate.
- Reply present in USB bulk-IN but absent from interface capture points to the
  kernel receive path rather than hardware filtering.

After any remedy, compare peer capture, standalone tshark and MCP using exact
identifiers/bytes in a common observation window. Test original and alternate
MACs, broadcast, VLAN and QinQ separately; preserve quality counters and USB
errors. Restore the original adapter configuration and verify normal connectivity.

## Implications for this MCP

- `promiscuous_enabled` records successful membership, not verified device-side
  filter programming.
- Successful spoofed-source transmission does not imply reply reception support.
- Switching from raw sockets to dumpcap does not fix frames discarded before
  either host capture path.
- This mechanism is separate from stripped VLAN metadata, which the receiver
  handles using `PACKET_AUXDATA`.

See [Known issues](../KNOWN_ISSUES.md) for broader platform and analysis limits.

## Primary sources

Branch source can advance beyond a running release; inspect the actual installed
modules/configuration as well as source before diagnosing another machine.

[ecm]: https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.y/drivers/net/usb/r8153_ecm.c
[usbnet]: https://sourcegraph.com/github.com/microsoft/WSL2-Linux-Kernel/-/blob/drivers/net/usb/usbnet.c#L1156
[cdc]: https://github.com/torvalds/linux/blob/v6.18/drivers/net/usb/cdc_ether.c
[usbnet-mac]: https://sourcegraph.com/github.com/torvalds/linux/-/blob/drivers/net/usb/usbnet.c#L1708
[eth]: https://github.com/torvalds/linux/blob/v6.18/net/ethernet/eth.c
[vendor]: https://sourcegraph.com/github.com/torvalds/linux/-/blob/drivers/net/usb/r8152.c#L9665
