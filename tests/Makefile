SHELL := /bin/sh

CC ?= cc
RUSTC ?= rustc
BUILD_DIR ?= ../build
UNIT_DIR := $(BUILD_DIR)/unit
CFLAGS ?= -O2 -g
override CFLAGS += -std=c11 -Wall -Wextra -Werror -pedantic
CPPFLAGS += -I../src/proto $(shell pkg-config --cflags openssl libsodium 2>/dev/null)
LDLIBS += $(shell pkg-config --libs openssl libsodium 2>/dev/null || printf '%s' '-lcrypto -lsodium')

.PHONY: test codec-test clean

test: $(UNIT_DIR)/test_nodeid $(UNIT_DIR)/test_setup $(UNIT_DIR)/test_ed25519 $(UNIT_DIR)/test_discovery $(UNIT_DIR)/test_mapping $(UNIT_DIR)/test_collision_fixture $(UNIT_DIR)/test_wire $(UNIT_DIR)/test_genl $(UNIT_DIR)/test_meshtastic $(UNIT_DIR)/test_radio $(UNIT_DIR)/test_usb_contract $(UNIT_DIR)/test_usb_attach $(UNIT_DIR)/test_reliability $(UNIT_DIR)/test_replay $(UNIT_DIR)/test_ordering $(UNIT_DIR)/test_airtime $(UNIT_DIR)/genl_vector_c $(UNIT_DIR)/genl_vector_rs
	@$(UNIT_DIR)/test_nodeid
	@$(UNIT_DIR)/test_setup
	@$(UNIT_DIR)/test_ed25519
	@$(UNIT_DIR)/test_discovery
	@$(UNIT_DIR)/test_mapping
	@$(UNIT_DIR)/test_collision_fixture
	@$(UNIT_DIR)/test_wire
	@$(UNIT_DIR)/test_genl
	@$(UNIT_DIR)/test_meshtastic
	@$(UNIT_DIR)/test_radio
	@$(UNIT_DIR)/test_usb_contract
	@$(UNIT_DIR)/test_usb_attach
	@$(UNIT_DIR)/test_reliability
	@$(UNIT_DIR)/test_replay
	@$(UNIT_DIR)/test_ordering
	@$(UNIT_DIR)/test_airtime
	@$(UNIT_DIR)/genl_vector_c > $(UNIT_DIR)/genl.c.bin
	@$(UNIT_DIR)/genl_vector_rs > $(UNIT_DIR)/genl.rs.bin
	@cmp $(UNIT_DIR)/genl.c.bin $(UNIT_DIR)/genl.rs.bin

codec-test: $(UNIT_DIR)/test_setup $(UNIT_DIR)/test_discovery $(UNIT_DIR)/test_wire $(UNIT_DIR)/test_genl $(UNIT_DIR)/test_meshtastic $(UNIT_DIR)/test_radio $(UNIT_DIR)/test_usb_contract $(UNIT_DIR)/test_usb_attach $(UNIT_DIR)/test_reliability $(UNIT_DIR)/test_replay $(UNIT_DIR)/test_ordering $(UNIT_DIR)/test_airtime
	@$(UNIT_DIR)/test_setup
	@$(UNIT_DIR)/test_discovery
	@$(UNIT_DIR)/test_wire
	@$(UNIT_DIR)/test_genl
	@$(UNIT_DIR)/test_meshtastic
	@$(UNIT_DIR)/test_radio
	@$(UNIT_DIR)/test_usb_contract
	@$(UNIT_DIR)/test_usb_attach
	@$(UNIT_DIR)/test_reliability
	@$(UNIT_DIR)/test_replay
	@$(UNIT_DIR)/test_ordering
	@$(UNIT_DIR)/test_airtime

$(UNIT_DIR):
	@mkdir -p "$@"

$(UNIT_DIR)/test_nodeid: unit/test_nodeid.c ../src/proto/nodeid.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

$(UNIT_DIR)/test_setup: unit/test_setup.c ../src/tools/setup.c ../src/proto/nodeid.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) -I../src/tools $(CFLAGS) $^ $(LDLIBS) -o $@

$(UNIT_DIR)/test_ed25519: unit/test_ed25519.c ../src/kernel/core/crypto/monocypher.c ../src/kernel/core/crypto/monocypher-ed25519.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) -I../src/kernel/core/crypto $(CFLAGS) $^ $(LDLIBS) -o $@

$(UNIT_DIR)/test_discovery: unit/test_discovery.c ../src/proto/wire.c ../src/kernel/core/crypto/monocypher.c ../src/kernel/core/crypto/monocypher-ed25519.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) -I../src/kernel/core/crypto $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_mapping: unit/test_mapping.c ../src/proto/mapping.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

$(UNIT_DIR)/test_collision_fixture: unit/test_collision_fixture.c ../src/proto/mapping.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

$(UNIT_DIR)/test_wire: unit/test_wire.c ../src/proto/wire.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_genl: unit/test_genl.c ../src/proto/genl.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_meshtastic: unit/test_meshtastic.c ../src/proto/meshtastic.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_radio: unit/test_radio.c ../src/proto/radio.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_usb_contract: unit/test_usb_contract.c ../src/kernel/usb/contract.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) -I../src/kernel/usb $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_usb_attach: unit/test_usb_attach.c ../src/tools/usb_attach.c ../src/kernel/usb/contract.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) -I../src/tools -I../src/kernel/usb $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_reliability: unit/test_reliability.c ../src/proto/reliability.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_replay: unit/test_replay.c ../src/proto/replay.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_ordering: unit/test_ordering.c ../src/proto/ordering.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/test_airtime: unit/test_airtime.c ../src/proto/airtime.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/genl_vector_c: unit/genl_vector.c ../src/proto/genl.c | $(UNIT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(UNIT_DIR)/genl_vector_rs: unit/genl_vector.rs | $(UNIT_DIR)
	$(RUSTC) -D warnings -o $@ $<

clean:
	@rm -rf "$(UNIT_DIR)"
