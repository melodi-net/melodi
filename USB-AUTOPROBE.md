Automatic interface creation on USB plug
===

Goal: plugging a Melodi radio creates `melN`, unplugging removes it, with no
manual step — the way a USB Ethernet adapter behaves.

Status: **implemented** for the current CDC firmware. Remote reflashing is
preserved. The vendor-class variant is documented in section 5 as future work.

---

## 1. What actually blocked it

Two separate things, and neither was the one assumed when this note was first
written.

**The descriptor was never the blocker.** Both attach paths — the USB driver
probe and the tty line discipline — called `melodi_attach_selected_transport()`,
which binds a radio only to an interface whose `radio_serial` already matches.
It returns `-ENODEV` for an unknown radio and never creates anything. So a
freshly plugged radio had nowhere to attach unless its serial had been declared
in advance through `radios=` or `melodi link set --usb-serial`.

`melodi_attach_transport()`, which does allocate an interface on demand, was
exported but unused by `melodi_usb`.

**The vendor-class route is blocked in the toolchain.** The arduino-pico core
ships `tusb_config.h` with an unguarded `#define CFG_TUD_VENDOR (0)`, so the
TinyUSB vendor class is compiled out and cannot be switched on with a build
flag. Adding a vendor interface means moving the firmware to
`-DUSE_TINYUSB` / Adafruit_TinyUSB, which rewrites how USB and `Serial` work.
That is the change most likely to break enumeration, and a board that fails to
enumerate can only be recovered with the physical BOOTSEL button.

---

## 2. What was implemented

### 2.1 Attach falls back to creating an interface

`melodi_attach_radio_transport()` in `src/kernel/core/main.c` tries the pinned
interface first, and when no interface claims that serial it allocates a new one
and stamps the serial on it. `melodi_usb` calls it from both attach paths.

Pinning still wins where it is configured, so `radios=SERIAL_A,SERIAL_B` keeps
its existing meaning and still gives stable naming.

### 2.2 udev hands the tty to the kernel directly

The `attach` module parameter parses `major:minor`, which udev already knows, so
the rule needs no helper binary and no systemd unit:

```
ACTION=="add", SUBSYSTEM=="tty", ENV{MELODI_RADIO}=="1", \
    RUN+="/bin/sh -c 'test -w /sys/module/melodi_usb/parameters/attach && \
          echo %M:%m > /sys/module/melodi_usb/parameters/attach'"
```

The `test -w` guard makes the rule a no-op when the modules are not loaded.

`melodi-radio-attach.service` now replays plug events with `udevadm trigger`
after `systemd-modules-load.service`, because radios plugged in before the
modules load would otherwise be missed at boot.

---

## 3. Resulting behaviour

```
plug   -> udev matches -> writes major:minor -> ldisc attaches
       -> melodi_attach_radio_transport() -> melN appears
unplug -> ldisc closes -> melodi_detach_transport() -> melN removed
```

Verified on hardware with modules loaded carrying no `radios=` pinning:

| step | interfaces |
| --- | --- |
| modules loaded | `mel0` |
| plug event | `mel0 mel1` |
| detach | `mel0` |
| plug event again | `mel0 mel1` |

Both radios bound themselves and reported their own serial and USB path.

---

## 4. Limits of the current design

`melodi_core` always creates one interface at load, and `interfaces=0` is
rejected, so `mel0` exists before any radio is plugged and persists after every
radio is unplugged. Only interfaces beyond the pre-created ones are created and
destroyed dynamically.

Interfaces are numbered in attach order, so which radio becomes `mel0` depends
on plug order. Use `radios=` or a udev rename keyed on `ID_SERIAL_SHORT` when
that matters.

The module still has to be loaded before a plug event does anything.
`MODULE_DEVICE_TABLE` covers only the emulated test device, so kmod will not
autoload `melodi_usb` for a real radio. `modules-load.d` loads it at boot.

---

## 5. Future work: vendor-class descriptor

Moving the radio onto a vendor-specific interface would let `melodi_usb_probe()`
claim the device directly, which removes udev from the path entirely and makes
`MODULE_DEVICE_TABLE` autoload the module on plug.

It requires, in order:

1. Firmware moved to Adafruit_TinyUSB so `CFG_TUD_VENDOR` can be enabled.
2. A vendor interface — class `0xff`, subclass `0x4d`, protocol `0x01`, two bulk
   endpoints — mirroring the existing test contract.
3. `MELODI_USB_CONTRACT_VENDOR` in `contract.h`, a matching branch in
   `melodi_usb_contract_validate()`, and a Feather entry in `melodi_usb_ids[]`.
4. `melodi_usb_probe()` accepting the new `driver_info` and skipping the CDC data
   interface lookup.

Do not drop CDC-ACM while remote. It carries the 1200-baud touch reset that
puts the board into its bootloader, and without it a bad flash needs someone
standing at the hardware. Either keep CDC alongside the vendor interface as a
composite device, or first add a `RESET` message to the host↔radio protocol that
calls `reset_usb_boot()`, and prove it works, before removing CDC.
