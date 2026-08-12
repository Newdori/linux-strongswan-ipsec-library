CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
RANLIB = $(CROSS_COMPILE)ranlib
SYSROOT ?=
BUILD_DIR ?= build/make
OUTPUT_DIR ?= lib
CPPFLAGS ?= -Iinclude -Isrc/internal -Isrc/vici -Isrc/xfrm -Isrc/route
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror
CFLAGS += -fPIC -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=
LDLIBS ?= -lpthread

ifneq ($(strip $(SYSROOT)),)
CPPFLAGS += --sysroot=$(SYSROOT)
LDFLAGS += --sysroot=$(SYSROOT)
endif

SOURCES := \
	src/core/error.c \
	src/core/ipsec.c \
	src/core/log.c \
	src/core/netlink.c \
	src/core/util.c \
	src/vici/vici_algorithm.c \
	src/vici/vici_client.c \
	src/vici/vici_connection.c \
	src/vici/vici_credential.c \
	src/vici/vici_packet.c \
	src/vici/vici_parser.c \
	src/vici/vici_sa.c \
	src/vici/vici_stats.c \
	src/vici/vici_transport.c \
	src/xfrm/xfrm_policy.c \
	src/xfrm/xfrm_state.c \
	src/xfrm/xfrm_stats.c \
	src/route/address.c \
	src/route/interface.c \
	src/route/route.c

OBJECTS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SOURCES))
STATIC_LIBRARY := $(OUTPUT_DIR)/libipsec_native.a
SHARED_LIBRARY := $(OUTPUT_DIR)/libipsec_native.so

.PHONY: all clean

all: $(STATIC_LIBRARY) $(SHARED_LIBRARY)

$(STATIC_LIBRARY): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(SHARED_LIBRARY): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(CC) -shared $(LDFLAGS) -Wl,-soname,libipsec_native.so.0 \
		-Wl,--version-script=src/libipsec_native.map -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(STATIC_LIBRARY) $(SHARED_LIBRARY)
