HOST_MAKEFILE = Makefile.host
ZYNQMP_MAKEFILE = Makefile.zynqmp

.PHONY: all host zynqmp clean clean_host clean_zynqmp

all: host zynqmp

host:
	$(MAKE) -f $(HOST_MAKEFILE) all

zynqmp:
	$(MAKE) -f $(ZYNQMP_MAKEFILE) all

clean: clean_host clean_zynqmp

clean_host:
	$(MAKE) -f $(HOST_MAKEFILE) clean

clean_zynqmp:
	$(MAKE) -f $(ZYNQMP_MAKEFILE) clean
