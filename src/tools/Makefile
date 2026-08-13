SHELL := /bin/sh

CC ?= cc
BUILD_DIR ?= ../../build/bin
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -pedantic
CPPFLAGS += -I../proto $(shell pkg-config --cflags openssl libsodium 2>/dev/null)
LDLIBS += $(shell pkg-config --libs openssl libsodium 2>/dev/null || printf '%s' '-lcrypto -lsodium')

.PHONY: all clean

all: $(BUILD_DIR)/melodi $(BUILD_DIR)/melsend $(BUILD_DIR)/melrecv $(BUILD_DIR)/melping

$(BUILD_DIR):
	@mkdir -p "$@"

$(BUILD_DIR)/melodi: melodi.c setup.c tpm.c usb_attach.c netlink.c ../proto/genl.c ../proto/nodeid.c ../kernel/usb/contract.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -I../kernel/usb $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD_DIR)/melsend: melsend.c client.c netlink.c ../proto/genl.c ../proto/nodeid.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD_DIR)/melrecv: melrecv.c client.c netlink.c ../proto/genl.c ../proto/nodeid.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD_DIR)/melping: melping.c client.c netlink.c ../proto/genl.c ../proto/nodeid.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

clean:
	@rm -f "$(BUILD_DIR)/melodi" "$(BUILD_DIR)/melsend" "$(BUILD_DIR)/melrecv" "$(BUILD_DIR)/melping"
