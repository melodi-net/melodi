SHELL := /bin/sh

CLANG ?= clang
BUILD_DIR ?= ../../build/fuzz
TARGET := $(BUILD_DIR)/parsers
CORPUS := $(BUILD_DIR)/corpus
SEED := $(CORPUS)/zero-512
SOURCES := parsers.c ../../src/proto/genl.c ../../src/proto/meshtastic.c ../../src/proto/wire.c
CFLAGS := -O1 -g -std=c11 -Wall -Wextra -Werror -pedantic
CFLAGS += -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined
CPPFLAGS := -I../../src/proto

.PHONY: run clean

run: $(TARGET) $(SEED)
	@$(TARGET) -seed=1 -runs=50000 -max_len=8192 -timeout=5 \
		-verbosity=0 "$(CORPUS)"

$(TARGET): $(SOURCES)
	@mkdir -p "$(BUILD_DIR)"
	$(CLANG) $(CPPFLAGS) $(CFLAGS) $^ -o $@

$(SEED):
	@mkdir -p "$(CORPUS)"
	@dd if=/dev/zero of="$@" bs=512 count=1 status=none

clean:
	@rm -rf "$(BUILD_DIR)"
