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

    if (2 > iArgumentCount) {
        return FailAppConfigTest("one or more configuration paths are required");
    }
    else {
        eError = IPSEC_OK;
    }
    for (iIndex = 1; iIndex < iArgumentCount; iIndex++) {
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
    (void)printf("v15 application configuration parser passed: %d files\n",
                 iArgumentCount - 1);
    return 0;
}
