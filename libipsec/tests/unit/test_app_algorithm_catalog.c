#include "app_internal.h"

#include <stdio.h>
#include <string.h>

static int32_t CheckNativeAppAlgorithmCase(
    NativeAppAlgorithmMode_t eMode,
    uint32_t uiIndex,
    const NativeAppConfig_t *pConfig)
{
    NativeAppAlgorithmCase_t Case;
    IpsecError_t eError;

    eError = GetNativeAppAlgorithmCase(eMode, uiIndex, pConfig, NULL, NULL,
                                       &Case);
    if ((IPSEC_OK != eError) || ('\0' == Case.acId[0]) ||
        ('\0' == Case.acIkeProposal[0]) ||
        ('\0' == Case.acEspProposal[0])) {
        (void)fprintf(stderr, "failed to generate mode=%s index=%u\n",
                      GetNativeAppAlgorithmModeName(eMode), uiIndex);
        return 1;
    }
    else {
        return 0;
    }
}

static int32_t CheckNativeAppAlgorithmCatalog(
    NativeAppAlgorithmMode_t eMode,
    const NativeAppConfig_t *pConfig)
{
    uint32_t uiCount = GetNativeAppAlgorithmCaseCount(eMode);
    uint32_t uiIndex;

    for (uiIndex = 0U; uiIndex < uiCount; uiIndex++) {
        if (0 != CheckNativeAppAlgorithmCase(eMode, uiIndex, pConfig)) {
            return 1;
        }
        else {
            /* Continue through the complete generated catalog. */
        }
    }
    return 0;
}

int main(void)
{
    NativeAppConfig_t Config = {0};
    NativeAppAlgorithmCase_t Case;
    uint32_t uiBaselineCount = GetNativeAppAlgorithmCaseCount(
        NATIVE_APP_ALGORITHM_BASELINE);
    uint32_t uiIkeCount = GetNativeAppAlgorithmCaseCount(
        NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE);
    uint32_t uiEspCount = GetNativeAppAlgorithmCaseCount(
        NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP);
    int32_t iFailed = 0;

    (void)snprintf(Config.acIkeProposals, sizeof(Config.acIkeProposals),
                   "%s", "aes256-sha256-prfsha256-modp2048");
    (void)snprintf(Config.acEspProposals, sizeof(Config.acEspProposals),
                   "%s", "aes256-sha256");

    if ((54U != uiBaselineCount) || (18172U != uiIkeCount) ||
        (4876U != uiEspCount)) {
        (void)fprintf(stderr,
                      "unexpected counts: baseline=%u ike=%u esp=%u\n",
                      uiBaselineCount, uiIkeCount, uiEspCount);
        iFailed = 1;
    }
    else {
        iFailed |= CheckNativeAppAlgorithmCatalog(
            NATIVE_APP_ALGORITHM_BASELINE, &Config);
        iFailed |= CheckNativeAppAlgorithmCatalog(
            NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE, &Config);
        iFailed |= CheckNativeAppAlgorithmCatalog(
            NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP, &Config);
    }

    if (IPSEC_OK != GetNativeAppAlgorithmCase(
            NATIVE_APP_ALGORITHM_CUSTOM, 0U, &Config,
            "aes256-sha256-prfsha256-modp2048",
            "aes256-sha256-ecp256-esn", &Case)) {
        (void)fprintf(stderr, "failed to generate custom case\n");
        iFailed = 1;
    }
    else if (!Case.bSeparateChildExchange || !Case.bExpectEsn ||
             (0 != strcmp("ECP_256", Case.acExpectedChildKe))) {
        (void)fprintf(stderr, "custom case metadata mismatch\n");
        iFailed = 1;
    }
    else {
        /* Custom PFS and ESN metadata is correct. */
    }

    if ((0 != strcmp("none",
                     GetNativeAppAlgorithmErrorText(IPSEC_OK))) ||
        (0 != strcmp("invalid argument", GetNativeAppAlgorithmErrorText(
            IPSEC_ERR_INVALID_ARGUMENT)))) {
        (void)fprintf(stderr, "algorithm error text mismatch\n");
        iFailed = 1;
    }
    else {
        /* Success and failure use distinct error field text. */
    }

    if (0 == iFailed) {
        (void)printf("algorithm catalog tests passed\n");
    }
    else {
        /* The detailed failure was already printed. */
    }
    return iFailed;
}
