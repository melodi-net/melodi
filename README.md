Melodi
===

Melodi is a native message network stack for Linux, built as loadable kernel
modules. It does not run over IP, CAN, Ethernet or any other Linux network
protocol. Applications address peers by a 33 byte cryptographic NodeId and a
16 bit service number, and the kernel carries those messages over LoRa radio.

Load the modules, attach a radio, and Linux exposes `mel0`.

---

## What it is

```text
application
    │  Generic Netlink family "melodi"
    │  destination = 33 byte NodeId + 16 bit service
    ▼
mel0                       ARPHRD_NONE netdevice, never IP
    ▼
melodi_core.ko             identity, discovery, routing, encryption,
    │                      fragmentation, reliability, ordering,
    │                      queues and airtime governance
    ▼
melodi_usb.ko              radio transport over an exact USB serial
    ▼
Melodi radio firmware      LoRa modem
```

The core owns every hardware independent behaviour. A backend owns only the
physical transport. The radio is a modem: it accepts a packet, transmits it,
receives a packet and hands it up. It never parses a Melodi frame.

`melodi_loop.ko` provides an in-kernel virtual radio pair with deterministic
fault injection, so the whole stack can be exercised without hardware.

## Addressing

A NodeId is a versioned 33 byte value derived from an Ed25519 public key. It
survives reboot, radio replacement and locator changes. Inside authenticated
frames a NodeId maps deterministically to a 32 bit native locator, which is
also the address the radio uses on air. Applications never see it.

Peers authenticate with signed ephemeral key exchange, and traffic is
encrypted with per session keys under replay protection.

## Repository layout

| Path | Contents |
| --- | --- |
| `src/kernel/core` | `melodi_core.ko`, the complete protocol stack |
| `src/kernel/usb` | `melodi_usb.ko`, the radio backend and line discipline |
| `src/kernel/loop` | `melodi_loop.ko`, the virtual radio pair |
| `src/proto` | codecs shared by the kernel, tools and firmware |
| `src/tools` | `melodi`, `melsend`, `melrecv`, `melping` |
| `src/examples` | the same exchange in C, C++, Rust, Go and Zig |
| `src/install` | udev rules, systemd units and packaging inputs |
| `tests` | unit, fuzz, sanitizer, VM, emulation and hardware lanes |

`PLAN.md` is the normative specification. Where this README and `PLAN.md`
disagree, `PLAN.md` wins.

## Build

The root Makefile is the only supported entrypoint. Modules build as external
modules against the running distribution kernel; Linux is never rebuilt.

```sh
nix develop --impure
make verify
```

`make verify` runs the architecture gate, the comment gate, the module build,
the tools and examples, the host unit tests, cppcheck and the TPM smoke test.

## Install

```sh
sudo make install
sudo make rules
sudo modprobe melodi_core radios=SERIAL_A,SERIAL_B
sudo modprobe melodi_usb
sudo melodi tty scan
ip -details link show mel0
```

Radios are bound by exact USB serial, never by port path or enumeration
order. See `src/install/README.md` for identity provisioning, TPM backed keys,
policy configuration and kernel upgrades.

## Use

```sh
melodi identity generate /etc/melodi/mel0.key
melodi identity load -i mel0 --generation 1 /etc/melodi/mel0.key
ip link set dev mel0 up
melodi status -i mel0
melodi id -i mel0

melrecv -i mel0 12345
melsend --reliable -i mel0 <NODE_ID> 12345 "hello"
melping -i mel0 <NODE_ID>
```

## Radio firmware

The companion firmware in
[melodi-net/firmware](https://github.com/melodi-net/firmware) turns a LoRa
board into a Melodi modem. Both sides compile the same `src/proto/radio.c`, so
the host and radio codecs cannot drift apart. Clone it beside this repository:

```text
melodi/
├── melodi/     this repository
└── firmware/   the radio firmware
```

The host owns all radio parameters. `melodi_usb` module parameters set them:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `frequency` | 868100000 | carrier in hertz |
| `bandwidth` | 125 | channel bandwidth in kilohertz |
| `spreading` | 9 | spreading factor, 6 to 12 |
| `coding` | 5 | coding rate denominator, 5 to 8 |
| `power` | 14 | transmit power in dBm |
| `duty` | 100 | duty budget in permille |

## Status

Working and covered by tests: the protocol core, the Generic Netlink UAPI, the
virtual radio pair, the native radio link protocol, identity and policy
tooling, packaging and install lanes.

Not yet completed: real hardware acceptance over the native firmware, and
multi-hop relaying, which the current modem does not implement.

## License

GPL-2.0-only. See `LICENSE`.
