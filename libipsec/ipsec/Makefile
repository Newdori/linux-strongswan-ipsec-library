HOST_MAKEFILE = Makefile.host
ZYNQMP_MAKEFILE = Makefile.zynqmp

.PHONY: all host zynqmp clean clean_host clean_zynqmp

all: host zynqmp

ifneq ($(filter clean,$(MAKECMDGOALS)),)
host zynqmp:
	@:
else
host:
	$(MAKE) -f $(HOST_MAKEFILE) all

zynqmp:
	$(MAKE) -f $(ZYNQMP_MAKEFILE) all
endif

CLEAN_TARGETS =

ifneq ($(filter host,$(MAKECMDGOALS)),)
CLEAN_TARGETS += clean_host
endif

ifneq ($(filter zynqmp,$(MAKECMDGOALS)),)
CLEAN_TARGETS += clean_zynqmp
endif

ifeq ($(strip $(CLEAN_TARGETS)),)
CLEAN_TARGETS = clean_host clean_zynqmp
endif

clean: $(CLEAN_TARGETS)

clean_host:
	$(MAKE) -f $(HOST_MAKEFILE) clean

clean_zynqmp:
	$(MAKE) -f $(ZYNQMP_MAKEFILE) clean
