# linux-strongswan-ipsec-library

Native C11 strongSwan/IPsec control and status library for Linux. The project
uses VICI IPC to control a separately running `charon` daemon and Linux native
interfaces to query XFRM and network state. It does not invoke `swanctl`, `ip`,
`systemctl`, or another shell command from the library.

Project sources and detailed documentation are under
[`libipsec_native`](libipsec_native/README.md).

## Quick build on Ubuntu

```sh
cd libipsec_native
make clean
make -j"$(nproc)"
```

Outputs:

```text
libipsec_native/lib/libipsec_native.a
libipsec_native/lib/libipsec_native.so
```

## AArch64 cross build

```sh
cd libipsec_native
make clean
make -j"$(nproc)" CROSS_COMPILE=aarch64-linux-gnu-
```

PetaLinux deployment requirements and sysroot builds are documented in
[`docs/petalinux_compatibility.md`](libipsec_native/docs/petalinux_compatibility.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE),
[`NOTICE`](libipsec_native/NOTICE), and
[`THIRD_PARTY_NOTICES.md`](libipsec_native/THIRD_PARTY_NOTICES.md).
