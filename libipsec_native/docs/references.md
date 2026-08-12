# Interoperability references

- strongSwan VICI plugin and protocol:
  https://docs.strongswan.org/docs/latest/plugins/vici.html
- strongSwan swanctl connection configuration keys:
  https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html
- strongSwan project releases:
  https://github.com/strongswan/strongswan/releases
- Linux userspace API headers used by this project: `linux/netlink.h`,
  `linux/xfrm.h`, `linux/rtnetlink.h`, `linux/if_link.h`, `linux/if_addr.h`

The VICI wire encoder/decoder is independently implemented against the public
protocol format and the strongSwan 5.8.4 command schema. The product library
does not contain or link the strongSwan libvici implementation.
