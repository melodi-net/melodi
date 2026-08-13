SHELL := /bin/sh

CC ?= cc
CXX ?= c++
AR ?= ar
RUSTC ?= rustc
GO ?= go
ZIG ?= zig
BUILD_DIR ?= ../../build/bin
OBJECT_DIR := $(BUILD_DIR)/examples
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -pedantic
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -Werror -pedantic
CPPFLAGS += -I../proto -I../tools $(shell pkg-config --cflags libsodium 2>/dev/null)
CGO_CPPFLAGS := -I$(abspath ../proto) -I$(abspath ../tools) \
	$(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS := $(shell pkg-config --libs libsodium 2>/dev/null || printf '%s' '-lsodium')
CLIENT_OBJECTS := $(OBJECT_DIR)/client.o $(OBJECT_DIR)/netlink.o \
	$(OBJECT_DIR)/genl.o $(OBJECT_DIR)/nodeid.o
CLIENT_LIBRARY := $(OBJECT_DIR)/libmelodi_client.a
EXAMPLES := $(BUILD_DIR)/melodi-example-c $(BUILD_DIR)/melodi-example-cpp \
	$(BUILD_DIR)/melodi-example-rust $(BUILD_DIR)/melodi-example-go \
	$(BUILD_DIR)/melodi-example-zig

.PHONY: all clean

all: $(EXAMPLES)

$(OBJECT_DIR):
	@mkdir -p "$@"

$(OBJECT_DIR)/client.o: ../tools/client.c | $(OBJECT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJECT_DIR)/netlink.o: ../tools/netlink.c | $(OBJECT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJECT_DIR)/genl.o: ../proto/genl.c | $(OBJECT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJECT_DIR)/nodeid.o: ../proto/nodeid.c | $(OBJECT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(CLIENT_LIBRARY): $(CLIENT_OBJECTS)
	$(AR) rcs $@ $^

$(BUILD_DIR)/melodi-example-c: native.c $(CLIENT_LIBRARY)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(CLIENT_LIBRARY) $(SODIUM_LIBS) -o $@

$(BUILD_DIR)/melodi-example-cpp: native.cpp $(CLIENT_LIBRARY)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< $(CLIENT_LIBRARY) $(SODIUM_LIBS) -o $@

$(BUILD_DIR)/melodi-example-rust: native.rs $(CLIENT_LIBRARY)
	$(RUSTC) -D warnings -L "$(OBJECT_DIR)" -l static=melodi_client \
		-L $$(pkg-config --variable=libdir libsodium) -l dylib=sodium -o $@ $<

$(BUILD_DIR)/melodi-example-go: native.go $(CLIENT_LIBRARY)
	CGO_ENABLED=1 GO111MODULE=off \
	CGO_CFLAGS="$(CGO_CPPFLAGS)" \
	CGO_LDFLAGS="$(CLIENT_LIBRARY) $(SODIUM_LIBS)" \
		$(GO) build -o $@ $<

$(BUILD_DIR)/melodi-example-zig: native.zig $(CLIENT_LIBRARY)
	$(ZIG) build-exe -O ReleaseSafe -I../proto -I../tools \
		-L"$(OBJECT_DIR)" -lmelodi_client \
		-L$$(pkg-config --variable=libdir libsodium) -lsodium -lc \
		-femit-bin=$@ $<

clean:
	@rm -rf "$(OBJECT_DIR)" $(EXAMPLES)
