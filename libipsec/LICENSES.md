# Licensing boundary

libipsec is designed to be usable without linking to strongSwan's GPL libraries.

- It does not link to libstrongswan, libcharon, or strongSwan's GPL libvici.
- It communicates with the separately running charon process over the VICI wire protocol.
- It uses Linux UAPI headers for Netlink/XFRM/network status queries.
- No strongSwan GPL implementation source is copied into this library.

The VICI interoperability implementation was independently written from the published strongSwan 5.8.4 protocol description. strongSwan remains a separate program distributed under its own license.

The source project supplied as ipsec_app_project_v15 states that no open-source license is granted and that all rights are reserved. Code from that project has therefore not been copied into this library; its behavior and configuration semantics were analyzed as design input.

libipsec itself is licensed under the Apache License 2.0 in the
repository root `../LICENSE` file. This boundary record does not change the
licenses of strongSwan, Linux, or any other separately distributed software.
Commercial distributors should still review the final dependency set,
notices, and deployment architecture for their product.
