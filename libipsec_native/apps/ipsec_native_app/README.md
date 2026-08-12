# Native IPsec application

`ipsec_native_app` is a product-oriented control and status CLI linked to
`libipsec_native.a`. It reads the product-relevant fields from the existing v15
`key=value` configuration files. v15 capture, UDP traffic, matrix, firewall and
barrier settings are accepted only so the same file can be reused; those test
features are not executed.

The application never invokes `swanctl`, `ip`, `systemctl`, a shell, or another
command. Control uses VICI and status uses VICI, Netlink and `/proc` through the
library.

## Build

From the `libipsec_native` directory:

```sh
make -f Makefile.host clean all app
```

This creates the library under `lib` and the application in the project
directory:

```text
lib/libipsec_native.a
ipsec_native_app
```

Cross compilation follows the referenced `Makefile.host` convention:

```sh
make -f Makefile.host clean all app CROSS_COMPILE=aarch64-linux-gnu-
```

## Commands

```sh
./ipsec_native_app --config /path/pc_a_initiator.conf check
./ipsec_native_app --config /path/pc_a_initiator.conf load
./ipsec_native_app --config /path/pc_a_initiator.conf up
./ipsec_native_app --config /path/pc_a_initiator.conf status all
./ipsec_native_app --config /path/pc_a_initiator.conf status child
./ipsec_native_app --config /path/pc_a_initiator.conf rekey-child
./ipsec_native_app --config /path/pc_a_initiator.conf down
```

`up` loads the connection and PSK, then initiates and waits for an installed
CHILD SA for an initiator configuration. For a responder configuration it
loads the resources and waits for the peer to establish the CHILD SA.

Status scopes are `daemon`, `connections`, `ike`, `child`, `algorithms`,
`xfrm-state`, `xfrm-policy`, `xfrm-stat`, `interfaces`, `addresses`, `routes`,
and `all`.

## Live loop verification

Use a dedicated connection name and test peer. Each iteration loads the
connection, establishes the IKE/CHILD SA, checks the VICI SA state, verifies a
matching `reqid` in kernel XFRM state and policy, terminates the SA, waits until
VICI and XFRM entries disappear, and unloads the connection.

```sh
./ipsec_native_app --config /path/pc_a_initiator.conf loop \
    --count 100 --delay-ms 500
```

The loop is supported for the initiator role because a responder cannot drive
the remote peer's initiation schedule. `Ctrl-C` stops after cleanup of the
current iteration. Add `--continue-on-error` to collect multiple failures.

Credentials are retained by default because VICI `clear-creds` affects the
daemon-wide credential set, including other clients. Use
`--clear-credentials` only on a dedicated validation daemon.
