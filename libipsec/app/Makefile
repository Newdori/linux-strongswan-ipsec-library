TARGET ?= x86_64
CROSS_COMPILE ?=
ZYNQMP_CROSS_COMPILE ?= aarch64-linux-gnu-
SYSROOT ?=

ifneq ($(filter default undefined,$(origin CC)),)
CC = $(CROSS_COMPILE)gcc
endif

MKDIR_P ?= mkdir -p
RM_RF ?= rm -rf

CPPFLAGS += -I../include -I.
CFLAGS += -g -O2 -std=c11
CFLAGS += -Wall -Wextra -Wpedantic -Werror
CFLAGS += -D_POSIX_C_SOURCE=200809L
LDLIBS += -lpthread

ifneq ($(strip $(SYSROOT)),)
CPPFLAGS += --sysroot=$(SYSROOT)
LDFLAGS += --sysroot=$(SYSROOT)
endif

ifeq ($(TARGET),zynqmp)
LIBRARY_TARGET = zynqmp
LIBRARY = ../lib/zynqmp/libipsec.a
else ifeq ($(TARGET),x86_64)
LIBRARY_TARGET = host
LIBRARY = ../lib/x86_64/libipsec.a
else
$(error Unsupported TARGET '$(TARGET)'; use x86_64 or zynqmp)
endif

OBJECT_DIR = obj/$(TARGET)
OUTPUT_DIR = bin/$(TARGET)
APPLICATION = $(OUTPUT_DIR)/ipsec_app

SOURCES = \
	algorithm_catalog.c \
	algorithm_report.c \
	algorithm_runner.c \
	cli.c \
	command.c \
	config.c \
	lifecycle.c \
	show.c \
	main.c

OBJECTS = $(patsubst %.c,$(OBJECT_DIR)/%.o,$(SOURCES))
DEPFILES = $(OBJECTS:.o=.d)

.PHONY: all host zynqmp build library clean clean_host clean_zynqmp

all: host

host:
	$(MAKE) build TARGET=x86_64 CROSS_COMPILE="$(CROSS_COMPILE)" \
		SYSROOT="$(SYSROOT)"

zynqmp:
	$(MAKE) build TARGET=zynqmp \
		CROSS_COMPILE="$(if $(strip $(CROSS_COMPILE)),$(CROSS_COMPILE),$(ZYNQMP_CROSS_COMPILE))" \
		SYSROOT="$(SYSROOT)"

build: $(APPLICATION)

library:
	$(MAKE) -C ../ipsec $(LIBRARY_TARGET) CROSS_COMPILE="$(CROSS_COMPILE)" \
		CC="$(CC)" SYSROOT="$(SYSROOT)"

$(APPLICATION): library $(OBJECTS)
	@$(MKDIR_P) $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBRARY) $(LDLIBS)

$(OBJECT_DIR)/%.o: %.c
	@$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -o $@ -c $<

-include $(DEPFILES)

clean: clean_host clean_zynqmp

clean_host:
	$(RM_RF) obj/x86_64 bin/x86_64

clean_zynqmp:
	$(RM_RF) obj/zynqmp bin/zynqmp
