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
make -C app clean_host
make -C app host
```

For ZynqMP with the default `aarch64-linux-gnu-` prefix:

```sh
make -C app clean_zynqmp
make -C app zynqmp
```

Override the compiler prefix and PetaLinux sysroot when required:

```sh
make -C app zynqmp \
    CROSS_COMPILE=aarch64-linux-gnu- \
    SYSROOT=/path/to/petalinux/sysroot
```

Outputs are separated by architecture:

```text
lib/x86_64/libipsec.a
app/obj/x86_64/*.o
app/bin/x86_64/ipsec_app

lib/zynqmp/libipsec.a
app/obj/zynqmp/*.o
app/bin/zynqmp/ipsec_app
```

## Start a session

Start with an existing v15 endpoint configuration:

```sh
./app/bin/x86_64/ipsec_app --config /path/pc_a_initiator.conf
```

Or connect first with the defaults and build the configuration in memory:

```sh
./app/bin/x86_64/ipsec_app
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

show [SCOPE]
show SCOPE detail [NAME]
show SCOPE [NAME]
up
down
test loop [--count N] [--delay-ms N] [--continue-on-error]
test algorithm count MODE
test algorithm check MODE
test algorithm serve [--port N]
test algorithm run MODE [--start N] [--limit N|--all]
    [--port N] [--results FILE] [--delay-ms N] [--stop-on-error]
    [--ike PROPOSAL --esp PROPOSAL]
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

Show scopes are `summary`, `all`, `config`, `credential`, `daemon`,
`connections`, `ike`, `child`, `algorithms`, `xfrm`, `xfrm-state`,
`xfrm-policy`, `xfrm-stat`, `network`, `interfaces`, `addresses`, and
`routes`. Running `show` without a scope displays `summary`.

`show connections`, `show ike`, and `show child` use one-row-per-object tables
so that simultaneous peers can be compared without scrolling through record
blocks. Use `detail` to display every field represented by the corresponding
public result structure. Examples:

```text
show
show ike
show ike app-test
show ike detail
show ike detail app-test
show child detail app-test-child
```

The optional name filters `connections` and `ike` by their object name.
`child` accepts either a CHILD name or its parent IKE name. Long values are
visually truncated only in compact tables; `detail` always prints the complete
value held by the library.

The library API can load and control multiple uniquely named connections in
one context. This application intentionally owns one in-memory configuration
profile per CLI session. A product that requires simultaneous one-to-many
operation should maintain multiple profiles and call the public library API
with unique connection and CHILD names.

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

## Algorithm negotiation verification

Algorithm verification is an application test feature and is not part of the
product library API. It uses Native VICI and XFRM without running v15,
`swanctl`, or `ip` commands. The built-in catalogs preserve the v15 testcase
dimensions:

```text
baseline         54 cases
exhaustive-ike   18,172 cases
exhaustive-esp    4,876 cases
```

Run the responder application first on PC-B with a responder configuration:

```text
ipsec> test algorithm serve
```

Then run a small smoke range on PC-A with the matching initiator
configuration:

```text
ipsec> test algorithm count baseline
ipsec> test algorithm check baseline
ipsec> test algorithm run baseline --limit 3
```

The applications synchronize over UDP port `39001` by default. The configured
local/remote addresses must be reachable and the host firewall must permit
that port. `PREPARE` is exchanged before SA creation; the `VERIFY` request and
response are exchanged after CHILD installation, so a passing case also
confirms traffic in both directions across the installed policy. Use the same
`--port N` value on both peers to override the default.

`test algorithm serve` owns the PC-B CLI while it is waiting for a run, so
commands typed during that wait are not CLI commands. On normal completion,
PC-A sends a `FINISH` message and PC-B automatically returns to the `ipsec>`
prompt. Ctrl-C remains available to stop a responder whose initiator ended
abnormally. Run `show connections`, `show ike`, `show child`, and
`show xfrm-state` only after the prompt has returned.

Each case loads a connection, establishes IKE/CHILD, checks the negotiated
proposals, checks PFS and ESN when requested, verifies matching XFRM state and
policy, tests the protected data path, terminates the SA, verifies removal,
and unloads the connection. PSK credentials are loaded once per test process
and are not cleared automatically because VICI credential clearing is
daemon-wide.

Every run creates v15-style result directories under `output_root`, which
defaults to `./results`. PC-A sends its run ID to PC-B so corresponding folders
use the same timestamp and mode:

```text
results/baseline_20260813_143000_1234_initiator/
    application.log
    results.json
results/baseline_20260813_143000_1234_responder/
    application.log
```

`results.json` is checkpointed after every case and remains available after a
test failure or Ctrl-C. `--results FILE` selects its filename inside the newly
created initiator result directory; directory components are intentionally
ignored. Change the root before running with `config set output_root DIR` or
the v15-compatible `output_root=DIR` configuration setting:

```text
ipsec> test algorithm run baseline --all --results baseline-results.json
ipsec> test algorithm run exhaustive-ike --start 1 --limit 100 --results ike-part-001.json
ipsec> test algorithm run exhaustive-esp --all --results esp-results.json
ipsec> test algorithm run custom --ike aes256-sha256-prfsha256-modp2048 --esp aes256-sha256-modp2048-esn
```

Exhaustive modes intentionally default to ten cases; use `--all` for the full
catalog or `--start`/`--limit` to split a long run. Tests continue after a
failed algorithm by default so JSON captures the whole requested range. Add
`--stop-on-error` for a diagnostic run that should stop at the first failure.
Each run uses a new timestamped directory, so previous JSON and application
logs are retained.
