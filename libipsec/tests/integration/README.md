# Live integration test

Run this test only on a dedicated Linux strongSwan test host. It loads a VICI
connection and credential, establishes an SA with a configured peer, verifies
VICI and XFRM status, then removes the test state. Credential cleanup calls
ClearIpsecCredentials(), which clears all credentials loaded through VICI, so
do not use a production daemon.

Configure and build:

    cmake -S ipsec -B build -DIPSEC_NATIVE_BUILD_INTEGRATION_TESTS=ON
    cmake --build build --target test_live_ipsec

Required environment variables:

    IPSEC_TEST_LOCAL_ADDR
    IPSEC_TEST_REMOTE_ADDR
    IPSEC_TEST_LOCAL_ID
    IPSEC_TEST_REMOTE_ID
    IPSEC_TEST_LOCAL_TS
    IPSEC_TEST_REMOTE_TS
    IPSEC_TEST_IKE_PROPOSAL
    IPSEC_TEST_ESP_PROPOSAL
    IPSEC_TEST_PSK

Optional socket override:

    IPSEC_TEST_VICI_SOCKET=/run/charon.vici

Execute:

    ./build/test_live_ipsec

The test returns 77 when required environment is absent. PSK data is never
printed, but environment variables can be visible to privileged processes;
use disposable test credentials on an isolated host.

## Repeated lifecycle test using a v15 endpoint config

Build the application and use an initiator configuration with a live peer:

    make -C ipsec -f Makefile.host clean all app
    ./tests/integration/run_loop_test.sh \
      /path/to/ipsec_app_project_v15/configs/pc_a_initiator.conf 100 500

The same operation can be invoked directly:

    ./apps/bin/x86_64/ipsec_native_app --config /path/to/pc_a_initiator.conf loop \
      --count 100 --delay-ms 500

Every iteration checks IKE and CHILD state through VICI, matches the CHILD
`reqid` to at least one kernel XFRM state and policy, terminates the IKE SA,
waits for its VICI and XFRM state to disappear, and unloads the connection.
Use a dedicated connection name and daemon. Add `--clear-credentials` only if
clearing the daemon-wide VICI credential set is safe.
