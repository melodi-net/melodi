SHELL := /bin/sh

KDIR ?= /lib/modules/$(shell uname -r)/build
KERNELRELEASE ?= $(shell uname -r)
BUILD_DIR ?= $(CURDIR)/build
MODULE_BUILD_DIR := $(BUILD_DIR)/kernel
PREFIX ?= /usr
VERSION := 0.1.0
W ?= 1
KCFLAGS ?= -Werror
SIGN_HASH ?= sha256
SIGN_MODULE_DIR ?= $(MODULE_BUILD_DIR)
SIGN_MODULES ?= melodi_core melodi_usb

.DEFAULT_GOAL := build

.PHONY: all build modules tools examples test host-test verify architecture-check
.PHONY: static-check sparse-check
.PHONY: comment-check module-check module-install-smoke dkms-package dkms-smoke
.PHONY: sign-modules module-signing-smoke tpm-smoke
.PHONY: loop-smoke namespace-smoke language-smoke vm usb-emulation hardware-smoke
.PHONY: install-smoke upgrade-smoke uninstall-smoke fuzz-smoke sanitize
.PHONY: install uninstall install-modules install-tools install-config rules
.PHONY: format clean lock

all: build

build: modules tools examples

modules:
	@test -f src/kernel/Kbuild || { printf '%s\n' "missing src/kernel/Kbuild" >&2; exit 2; }
	@test -d "$(KDIR)" || { printf '%s\n' "missing kernel headers: $(KDIR)" >&2; exit 2; }
	@mkdir -p "$(MODULE_BUILD_DIR)"
	+$(MAKE) -C "$(KDIR)" M="$(CURDIR)/src/kernel" MO="$(MODULE_BUILD_DIR)" W="$(W)" KCFLAGS="$(KCFLAGS)" modules

tools:
	@mkdir -p "$(BUILD_DIR)/bin"
	@test ! -f src/tools/Makefile || $(MAKE) -C src/tools BUILD_DIR="$(BUILD_DIR)/bin"

examples: tools
	@test ! -f src/examples/Makefile || $(MAKE) -C src/examples BUILD_DIR="$(BUILD_DIR)/bin"

test: verify

host-test:
	@test ! -f tests/Makefile || $(MAKE) -C tests BUILD_DIR="$(BUILD_DIR)"

verify: architecture-check comment-check module-check tools examples host-test static-check tpm-smoke

architecture-check:
	@sh tests/architecture/check.sh

comment-check:
	@sh tests/architecture/comments.sh

static-check:
	@command -v cppcheck >/dev/null 2>&1 || { printf '%s\n' 'cppcheck is required' >&2; exit 2; }
	@cppcheck --enable=warning,performance,portability \
		--check-level=exhaustive --error-exitcode=1 --std=c11 \
		--suppress=missingIncludeSystem --quiet \
		src/proto src/tools tests/unit tests/fuzz

sparse-check:
	@command -v sparse >/dev/null 2>&1 || { printf '%s\n' 'sparse is required' >&2; exit 2; }
	@test "$$($(KDIR)/scripts/checker-valid.sh sparse)" = 1 || { \
		printf '%s\n' 'sparse is too old for these kernel headers' >&2; exit 2; \
	}
	@mkdir -p "$(BUILD_DIR)/sparse"
	+$(MAKE) -C "$(KDIR)" M="$(CURDIR)/src/kernel" \
		MO="$(BUILD_DIR)/sparse" W="$(W)" KCFLAGS="$(KCFLAGS)" \
		C=2 CHECK=sparse CF='-Wbitwise -Wcontext' modules

module-check: modules
	@sh tests/module/check.sh "$(MODULE_BUILD_DIR)"

loop-smoke: build host-test
	@sh tests/module/loop-smoke.sh "$(BUILD_DIR)"

module-install-smoke: modules
	@sh tests/install/module-install-smoke.sh "$(CURDIR)" "$(BUILD_DIR)" "$(KERNELRELEASE)"

sign-modules: modules
	@test -n "$(SIGN_FILE)" || { printf '%s\n' 'SIGN_FILE is required' >&2; exit 2; }
	@test -x "$(SIGN_FILE)" || { printf '%s\n' "SIGN_FILE is not executable: $(SIGN_FILE)" >&2; exit 2; }
	@test -r "$(SIGN_KEY)" || { printf '%s\n' 'SIGN_KEY is not readable' >&2; exit 2; }
	@test -r "$(SIGN_CERT)" || { printf '%s\n' 'SIGN_CERT is not readable' >&2; exit 2; }
	@for module in $(SIGN_MODULES); do \
		file="$(SIGN_MODULE_DIR)/$$module.ko"; \
		test -f "$$file" || { printf '%s\n' "missing module: $$file" >&2; exit 2; }; \
		"$(SIGN_FILE)" "$(SIGN_HASH)" "$(SIGN_KEY)" "$(SIGN_CERT)" "$$file"; \
	done

module-signing-smoke: modules
	@sh tests/install/module-signing-smoke.sh "$(CURDIR)" "$(BUILD_DIR)" "$(KDIR)"

tpm-smoke: tools
	@sh tests/install/tpm-smoke.sh "$(BUILD_DIR)"

dkms-package: verify
	@sh tests/install/dkms-package.sh "$(CURDIR)" "$(BUILD_DIR)" "$(VERSION)"

dkms-smoke: dkms-package
	@sh tests/install/dkms-smoke.sh "$(CURDIR)" "$(BUILD_DIR)" \
		"$(VERSION)" "$(KDIR)" "$(KERNELRELEASE)" dkms-smoke

namespace-smoke: build
	@sh tests/module/namespace-smoke.sh "$(BUILD_DIR)"

language-smoke: build
	@sh tests/module/language-smoke.sh "$(BUILD_DIR)"

vm: build
	@VM_IMAGE="$(VM_IMAGE)" VM_IMAGE_FORMAT="$(VM_IMAGE_FORMAT)" \
		VM_SSH_KEY="$(VM_SSH_KEY)" VM_SSH_USER="$(VM_SSH_USER)" \
		VM_SSH_PORT="$(VM_SSH_PORT)" VM_MEMORY="$(VM_MEMORY)" \
		sh tests/vm/run.sh "$(CURDIR)" "$(BUILD_DIR)"

install-smoke: build
	@sh tests/install/install-smoke.sh "$(CURDIR)" "$(BUILD_DIR)" "$(KERNELRELEASE)"

uninstall-smoke: install-smoke
	@sh tests/install/uninstall-smoke.sh "$(CURDIR)" "$(BUILD_DIR)" "$(KERNELRELEASE)"

usb-emulation: build
	@sh tests/usb/emulation.sh "$(BUILD_DIR)"

hardware-smoke: build
	+@if test -n "$(SIGN_KEY)$(SIGN_CERT)"; then \
		$(MAKE) sign-modules SIGN_FILE="$(SIGN_FILE)" \
			SIGN_HASH="$(SIGN_HASH)" SIGN_KEY="$(SIGN_KEY)" \
			SIGN_CERT="$(SIGN_CERT)"; \
	fi
	@HARDWARE_SERIALS="$(HARDWARE_SERIALS)" \
		HARDWARE_FIRMWARES="$(HARDWARE_FIRMWARES)" \
		sh tests/hardware/smoke.sh "$(BUILD_DIR)"

upgrade-smoke: dkms-package
	@sh tests/install/upgrade-smoke.sh "$(CURDIR)" "$(BUILD_DIR)" \
		"$(VERSION)" "$(KERNELRELEASE)" "$(UPGRADE_KDIR)" \
		"$(UPGRADE_KERNELRELEASE)"

fuzz-smoke:
	@$(MAKE) -C tests/fuzz BUILD_DIR="$(BUILD_DIR)/fuzz" run

sanitize:
	@ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		$(MAKE) -C tests CC=clang BUILD_DIR="$(BUILD_DIR)/sanitize/asan" \
		CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' test
	@MSAN_OPTIONS=halt_on_error=1 \
		$(MAKE) -C tests CC=clang BUILD_DIR="$(BUILD_DIR)/sanitize/msan" \
		CFLAGS='-O1 -g -fsanitize=memory -fno-omit-frame-pointer -fPIE -pie' \
		codec-test

format:
	@files=$$(find src tests -type f \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null); \
	if test -n "$$files"; then clang-format -i $$files; fi

clean:
	@if test -f src/kernel/Kbuild && test -d "$(KDIR)"; then \
		$(MAKE) -C "$(KDIR)" M="$(CURDIR)/src/kernel" MO="$(MODULE_BUILD_DIR)" clean; \
	fi
	@rm -rf "$(BUILD_DIR)"

lock:
	nix flake lock

install: build install-modules install-tools install-config
	@if test "$(SKIP_DEPMOD)" != 1; then depmod -b "$(DESTDIR)" "$(KERNELRELEASE)"; fi

install-modules: modules
	@install -d "$(DESTDIR)/lib/modules/$(KERNELRELEASE)/updates/melodi"
	@install -m 0644 "$(MODULE_BUILD_DIR)/melodi_core.ko" "$(DESTDIR)/lib/modules/$(KERNELRELEASE)/updates/melodi/melodi_core.ko"
	@install -m 0644 "$(MODULE_BUILD_DIR)/melodi_usb.ko" "$(DESTDIR)/lib/modules/$(KERNELRELEASE)/updates/melodi/melodi_usb.ko"

install-tools: tools
	@install -d "$(DESTDIR)$(PREFIX)/bin"
	@install -m 0755 "$(BUILD_DIR)/bin/melodi" "$(DESTDIR)$(PREFIX)/bin/melodi"
	@install -m 0755 "$(BUILD_DIR)/bin/melsend" "$(DESTDIR)$(PREFIX)/bin/melsend"
	@install -m 0755 "$(BUILD_DIR)/bin/melrecv" "$(DESTDIR)$(PREFIX)/bin/melrecv"
	@install -m 0755 "$(BUILD_DIR)/bin/melping" "$(DESTDIR)$(PREFIX)/bin/melping"

install-config:
	@install -d "$(DESTDIR)/etc/melodi"
	@install -d "$(DESTDIR)$(PREFIX)/lib/modules-load.d"
	@install -d "$(DESTDIR)$(PREFIX)/lib/udev/rules.d"
	@install -d "$(DESTDIR)$(PREFIX)/lib/systemd/system"
	@install -d "$(DESTDIR)$(PREFIX)/share/doc/melodi"
	@install -m 0644 src/install/melodi.conf "$(DESTDIR)$(PREFIX)/lib/modules-load.d/melodi.conf"
	@install -m 0644 src/install/99-melodi.rules "$(DESTDIR)$(PREFIX)/lib/udev/rules.d/99-melodi.rules"
	@install -m 0644 src/install/melodi-setup@.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/melodi-setup@.service"
	@install -m 0644 src/install/melodi-radio-attach.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/melodi-radio-attach.service"
	@install -m 0644 src/install/README.md "$(DESTDIR)$(PREFIX)/share/doc/melodi/README.md"
	@install -m 0644 src/install/mel0.conf.example "$(DESTDIR)$(PREFIX)/share/doc/melodi/mel0.conf.example"

rules:
	@install -d "$(DESTDIR)$(PREFIX)/lib/udev/rules.d"
	@install -m 0644 src/install/99-melodi.rules "$(DESTDIR)$(PREFIX)/lib/udev/rules.d/99-melodi.rules"
	@if test -z "$(DESTDIR)" && command -v udevadm >/dev/null 2>&1; then \
		udevadm control --reload; \
		udevadm trigger --subsystem-match=tty --action=change; \
	fi

uninstall:
	@rm -f "$(DESTDIR)/lib/modules/$(KERNELRELEASE)/updates/melodi/melodi_core.ko"
	@rm -f "$(DESTDIR)/lib/modules/$(KERNELRELEASE)/updates/melodi/melodi_usb.ko"
	@rmdir "$(DESTDIR)/lib/modules/$(KERNELRELEASE)/updates/melodi" 2>/dev/null || true
	@rm -f "$(DESTDIR)$(PREFIX)/bin/melodi"
	@rm -f "$(DESTDIR)$(PREFIX)/bin/melsend"
	@rm -f "$(DESTDIR)$(PREFIX)/bin/melrecv"
	@rm -f "$(DESTDIR)$(PREFIX)/bin/melping"
	@rm -f "$(DESTDIR)$(PREFIX)/lib/modules-load.d/melodi.conf"
	@rm -f "$(DESTDIR)$(PREFIX)/lib/udev/rules.d/99-melodi.rules"
	@rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/melodi-setup@.service"
	@rm -f "$(DESTDIR)$(PREFIX)/lib/systemd/system/melodi-radio-attach.service"
	@rm -f "$(DESTDIR)$(PREFIX)/share/doc/melodi/README.md"
	@rm -f "$(DESTDIR)$(PREFIX)/share/doc/melodi/mel0.conf.example"
	@rmdir "$(DESTDIR)$(PREFIX)/share/doc/melodi" 2>/dev/null || true
	@if test "$(SKIP_DEPMOD)" != 1; then depmod -b "$(DESTDIR)" "$(KERNELRELEASE)"; fi
