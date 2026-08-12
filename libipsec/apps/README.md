# Native IPsec interactive CLI

`ipsec_app` is an interactive control and status client linked to
`libipsec.a`. It connects to the configured strongSwan VICI socket once, keeps
the product configuration in memory, and waits at an `ipsec>` prompt. No
connection, credential, or SA is changed until the user enters a control
command.

The application never invokes `swanctl`, `ip`, `systemctl`, a shell, or another
command. Control uses VICI and status uses VICI, Netlink, and `/proc` through
the library. v15 capture, traffic, matrix, firewall, and barrier settings are
ignored so an existing endpoint configuration can still be reused.

## Build

From the `libipsec` directory:

```sh
make -C apps clean_host
make -C apps host
```

For ZynqMP with the default `aarch64-linux-gnu-` prefix:

```sh
make -C apps clean_zynqmp
make -C apps zynqmp
```

Override the compiler prefix and PetaLinux sysroot when required:

```sh
make -C apps zynqmp \
    CROSS_COMPILE=aarch64-linux-gnu- \
    SYSROOT=/path/to/petalinux/sysroot
```

Outputs are separated by architecture:

```text
lib/x86_64/libipsec.a
apps/obj/x86_64/*.o
apps/bin/x86_64/ipsec_app

lib/zynqmp/libipsec.a
apps/obj/zynqmp/*.o
apps/bin/zynqmp/ipsec_app
```

## Start a session

Start with an existing v15 endpoint configuration:

```sh
./apps/bin/x86_64/ipsec_app --config /path/pc_a_initiator.conf
```

Or connect first with the defaults and build the configuration in memory:

```sh
./apps/bin/x86_64/ipsec_app
```

`--verbose` enables informational and debug library logs. Error and warning
logs remain enabled by default. If a log is emitted while input is pending,
the callback prints it on a new line and restores the `ipsec>` prompt.

## Session commands

```text
config load FILE
config set KEY VALUE
config show
config validate

connection load
connection unload [NAME]
connection show

credential load
credential clear
credential show

ike initiate [NAME]
ike terminate [NAME]
ike rekey [NAME]
ike wait [NAME]

child initiate [NAME]
child terminate [NAME]
child rekey [NAME]
child wait [NAME]

status [SCOPE]
up
down
test loop [--count N] [--delay-ms N] [--continue-on-error]
help
exit
```

Quoted values and escaped spaces are accepted, for example:

```text
ipsec> config set local_id "product side a"
ipsec> config load "/opt/ipsec/configs/side a.conf"
```

`config show` never displays PSK contents. Configuration changes are rejected
while this session owns a loaded connection; unload it first. Loading or
changing a configuration resets the session's current-credential marker but
does not delete previously loaded daemon credentials. `credential clear` is
daemon-wide VICI behavior and must only be used when clearing credentials
owned by other clients is acceptable.

Status scopes are `daemon`, `connections`, `ike`, `child`, `algorithms`,
`xfrm-state`, `xfrm-policy`, `xfrm-stat`, `interfaces`, `addresses`, `routes`,
and `all`.

`up` and `down` are optional convenience commands. The independent
`connection`, `credential`, `ike`, and `child` commands are the primary product
control interface. Exiting the client does not automatically terminate or
unload daemon state.

## Explicit loop verification

The lifecycle loop is a validation command, not the application's default
behavior:

```text
ipsec> test loop --count 100 --delay-ms 500
```

Each iteration loads the connection, establishes the IKE/CHILD SA, checks
VICI state, verifies matching kernel XFRM state and policy, terminates the SA,
waits for state removal, and unloads the connection. Run it only with a
dedicated peer and connection name. Add `--clear-credentials` only on a
dedicated daemon because VICI credential clearing is daemon-wide.
