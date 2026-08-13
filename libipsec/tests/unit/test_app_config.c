#include "app_internal.h"

#include <stdio.h>
#include <string.h>

static int32_t FailAppConfigTest(const char *pcMessage)
{
    (void)fprintf(stderr, "app config test failed: %s\n", pcMessage);
    return 1;
}

int main(int iArgumentCount, char **ppcArguments)
{
    NativeAppConfig_t Config;
    NativeAppRuntimeConfig_t Runtime;
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;
    int32_t iIndex;

    InitializeNativeAppConfig(&Config);
    eError = SetNativeAppConfigSetting(&Config, "vici_uri", "");
    if ((IPSEC_OK != eError) ||
        (0 != strcmp("/run/charon.vici", Config.acViciSocket))) {
        return FailAppConfigTest("empty vici_uri did not select the default");
    }
    else {
        /* Continue with the supplied complete configurations. */
    }

    if (2 > iArgumentCount) {
        return FailAppConfigTest("one or more configuration paths are required");
    }
    else {
        eError = IPSEC_OK;
    }
    for (iIndex = 1;
         iIndex < ((4 == iArgumentCount) ? 2 : iArgumentCount);
         iIndex++) {
        eError = LoadNativeAppConfig(ppcArguments[iIndex], &Config, acError,
                                     sizeof(acError));
        if (IPSEC_OK == eError) {
            eError = BuildNativeAppRuntimeConfig(&Config, &Runtime, acError,
                                                 sizeof(acError));
        }
        else {
            /* Report the parser error below. */
        }
        if (IPSEC_OK != eError) {
            return FailAppConfigTest(acError);
        }
        else if ((1 == iIndex) &&
                 ((NATIVE_APP_ROLE_INITIATOR != Config.eRole) ||
                  (IPSEC_MODE_TRANSPORT != Config.eMode) ||
                  (60000U != Config.uiTimeoutMs) ||
                  (0 != strcmp("./results", Config.acOutputRoot)) ||
                  (0 != strcmp("/run/charon.vici", Config.acViciSocket)) ||
                  (0 != strcmp("192.0.2.10/32",
                               Runtime.acLocalTrafficSelector)) ||
                  (0 != strcmp("192.0.2.20/32",
                               Runtime.acRemoteTrafficSelector)) ||
                  (1U != Runtime.Connection.IkeProposals.uiCount) ||
                  (2U != Runtime.Connection.EspProposals.uiCount) ||
                  (IPSEC_ESN_ENABLED != Runtime.Connection.eEsn) ||
                  Runtime.Connection.bEnablePfs)) {
            return FailAppConfigTest(
                "converted values do not match v15 semantics");
        }
        else {
            /* This configuration is compatible. */
        }
    }
    if (4 == iArgumentCount) {
        eError = LoadNativeAppConfigFiles(
            ppcArguments[2], ppcArguments[3], &Config, acError,
            sizeof(acError));
        if ((IPSEC_OK != eError) ||
            (NATIVE_APP_ROLE_INITIATOR != Config.eRole) ||
            (IPSEC_MODE_TRANSPORT != Config.eMode) ||
            (60000U != Config.uiTimeoutMs) ||
            (39002U != Config.uiPeerPort) ||
            (0 != strcmp("192.0.2.10", Config.acPeerServerAddress)) ||
            ('\0' != Config.acRemoteAddress[0]) ||
            ('\0' != Config.acConnectionName[0]) ||
            (0 != strcmp("aes256-sha256-prfsha256-modp2048",
                         Config.acIkeProposals)) ||
            (0 != strcmp("aes256-sha256", Config.acEspProposals))) {
            return FailAppConfigTest(
                "split application/management configuration mismatch");
        }
        else {
            /* The split configuration remains incomplete until registration. */
        }
    }
    else {
        /* The legacy-only invocation remains supported. */
    }
    (void)printf("application configuration parser passed: %d files\n",
                 iArgumentCount - 1);
    return 0;
}
