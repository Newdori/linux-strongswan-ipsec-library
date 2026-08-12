#include "ipsec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INTEGRATION_PSK_MAX_LENGTH 4096U
#define INTEGRATION_WAIT_TIMEOUT_MS 30000U

typedef struct IntegrationInputs {
    const char *pcSocket;
    const char *pcLocalAddress;
    const char *pcRemoteAddress;
    const char *pcLocalId;
    const char *pcRemoteId;
    const char *pcLocalTrafficSelector;
    const char *pcRemoteTrafficSelector;
    const char *pcIkeProposal;
    const char *pcEspProposal;
    const char *pcPsk;
} IntegrationInputs_t;

static const char *GetRequiredEnvironment(const char *pcName)
{
    const char *pcValue = getenv(pcName);

    return ((NULL != pcValue) && ('\0' != pcValue[0])) ? pcValue : NULL;
}

static bool LoadIntegrationInputs(IntegrationInputs_t *pInputs)
{
    bool bLoaded;

    memset(pInputs, 0, sizeof(*pInputs));
    pInputs->pcSocket = getenv("IPSEC_TEST_VICI_SOCKET");
    pInputs->pcLocalAddress =
        GetRequiredEnvironment("IPSEC_TEST_LOCAL_ADDR");
    pInputs->pcRemoteAddress =
        GetRequiredEnvironment("IPSEC_TEST_REMOTE_ADDR");
    pInputs->pcLocalId = GetRequiredEnvironment("IPSEC_TEST_LOCAL_ID");
    pInputs->pcRemoteId = GetRequiredEnvironment("IPSEC_TEST_REMOTE_ID");
    pInputs->pcLocalTrafficSelector =
        GetRequiredEnvironment("IPSEC_TEST_LOCAL_TS");
    pInputs->pcRemoteTrafficSelector =
        GetRequiredEnvironment("IPSEC_TEST_REMOTE_TS");
    pInputs->pcIkeProposal =
        GetRequiredEnvironment("IPSEC_TEST_IKE_PROPOSAL");
    pInputs->pcEspProposal =
        GetRequiredEnvironment("IPSEC_TEST_ESP_PROPOSAL");
    pInputs->pcPsk = GetRequiredEnvironment("IPSEC_TEST_PSK");

    bLoaded = (NULL != pInputs->pcLocalAddress) &&
              (NULL != pInputs->pcRemoteAddress) &&
              (NULL != pInputs->pcLocalId) &&
              (NULL != pInputs->pcRemoteId) &&
              (NULL != pInputs->pcLocalTrafficSelector) &&
              (NULL != pInputs->pcRemoteTrafficSelector) &&
              (NULL != pInputs->pcIkeProposal) &&
              (NULL != pInputs->pcEspProposal) &&
              (NULL != pInputs->pcPsk) &&
              (strnlen(pInputs->pcPsk, INTEGRATION_PSK_MAX_LENGTH + 1U) <=
               INTEGRATION_PSK_MAX_LENGTH);
    return bLoaded;
}

static int32_t ReportIntegrationError(
    const char *pcOperation,
    IpsecError_t eError)
{
    (void)fprintf(stderr, "%s failed: %s\n", pcOperation,
                  GetIpsecErrorString(eError));
    return 1;
}

int main(void)
{
    IntegrationInputs_t Inputs;
    const char *apcLocalAddresses[1];
    const char *apcRemoteAddresses[1];
    const char *apcLocalTrafficSelectors[1];
    const char *apcRemoteTrafficSelectors[1];
    const char *apcIkeProposals[1];
    const char *apcEspProposals[1];
    const char *apcOwners[2];
    IpsecContext_t *pContext = NULL;
    IpsecIkeSaList_t IkeList = {0};
    IpsecChildSaList_t ChildList = {0};
    IpsecXfrmStateList_t StateList = {0};
    IpsecXfrmPolicyList_t PolicyList = {0};
    IpsecConfig_t Config = {.uiStructSize = sizeof(IpsecConfig_t)};
    IpsecConnectionConfig_t Connection = {
        .uiStructSize = sizeof(IpsecConnectionConfig_t)
    };
    IpsecPsk_t Psk = {.uiStructSize = sizeof(IpsecPsk_t)};
    IpsecControlOptions_t Control = {
        .uiStructSize = sizeof(IpsecControlOptions_t),
        .eMode = IPSEC_CONTROL_WAIT,
        .uiTimeoutMs = INTEGRATION_WAIT_TIMEOUT_MS
    };
    IpsecError_t eError;
    int32_t iResult = 1;
    bool bConnectionLoaded = false;
    bool bCredentialsLoaded = false;
    bool bInitiated = false;

    if (!LoadIntegrationInputs(&Inputs)) {
        (void)fprintf(stderr, "integration environment is incomplete\n");
        return 77;
    }
    else {
        /* Continue on a configured integration host. */
    }

    Config.pcViciSocketPath = Inputs.pcSocket;
    Config.uiCommandTimeoutMs = INTEGRATION_WAIT_TIMEOUT_MS;
    apcLocalAddresses[0] = Inputs.pcLocalAddress;
    apcRemoteAddresses[0] = Inputs.pcRemoteAddress;
    apcLocalTrafficSelectors[0] = Inputs.pcLocalTrafficSelector;
    apcRemoteTrafficSelectors[0] = Inputs.pcRemoteTrafficSelector;
    apcIkeProposals[0] = Inputs.pcIkeProposal;
    apcEspProposals[0] = Inputs.pcEspProposal;
    apcOwners[0] = Inputs.pcLocalId;
    apcOwners[1] = Inputs.pcRemoteId;

    Connection.pcName = "native-integration";
    Connection.pcChildName = "native-integration-child";
    Connection.LocalAddresses.ppcItems = apcLocalAddresses;
    Connection.LocalAddresses.uiCount = 1U;
    Connection.RemoteAddresses.ppcItems = apcRemoteAddresses;
    Connection.RemoteAddresses.uiCount = 1U;
    Connection.eLocalAuth = IPSEC_AUTH_PSK;
    Connection.eRemoteAuth = IPSEC_AUTH_PSK;
    Connection.pcLocalId = Inputs.pcLocalId;
    Connection.pcRemoteId = Inputs.pcRemoteId;
    Connection.IkeProposals.ppcItems = apcIkeProposals;
    Connection.IkeProposals.uiCount = 1U;
    Connection.EspProposals.ppcItems = apcEspProposals;
    Connection.EspProposals.uiCount = 1U;
    Connection.LocalTrafficSelectors.ppcItems = apcLocalTrafficSelectors;
    Connection.LocalTrafficSelectors.uiCount = 1U;
    Connection.RemoteTrafficSelectors.ppcItems = apcRemoteTrafficSelectors;
    Connection.RemoteTrafficSelectors.uiCount = 1U;
    Connection.eMode = IPSEC_MODE_TUNNEL;
    Connection.eEsn = IPSEC_ESN_AUTO;
    Connection.bEnableMobike = false;
    Connection.bEnableFragmentation = true;

    Psk.pcId = "native-integration-psk";
    Psk.pucData = (const uint8_t *)Inputs.pcPsk;
    Psk.uiDataLength = (uint32_t)strlen(Inputs.pcPsk);
    apcOwners[0] = Inputs.pcLocalId;
    apcOwners[1] = Inputs.pcRemoteId;
    Psk.Owners.ppcItems = apcOwners;
    Psk.Owners.uiCount = 2U;
    eError = InitializeIpsec(&pContext, &Config);
    if (IPSEC_OK != eError) {
        return ReportIntegrationError("InitializeIpsec", eError);
    }
    else {
        /* Context connected. */
    }

    eError = AddIpsecConnection(pContext, &Connection);
    if (IPSEC_OK == eError) {
        bConnectionLoaded = true;
        eError = AddIpsecPsk(pContext, &Psk);
    }
    else {
        /* Report below. */
    }
    if (IPSEC_OK == eError) {
        bCredentialsLoaded = true;
        eError = InitiateIpsecChild(pContext, Connection.pcChildName,
                                    &Control);
    }
    else {
        /* Report below. */
    }
    if (IPSEC_OK == eError) {
        bInitiated = true;
        eError = WaitIpsecChildInstalled(pContext, Connection.pcChildName,
                                         INTEGRATION_WAIT_TIMEOUT_MS);
    }
    else {
        /* Report below. */
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecIkeSas(pContext, &IkeList);
    }
    else {
        /* Report below. */
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecChildSas(pContext, &ChildList);
    }
    else {
        /* Report below. */
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecXfrmStates(pContext, &StateList);
    }
    else {
        /* Report below. */
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecXfrmPolicies(pContext, &PolicyList);
    }
    else {
        /* Report below. */
    }
    if ((IPSEC_OK == eError) && (0U < IkeList.uiCount) &&
        (0U < ChildList.uiCount) && (0U < StateList.uiCount) &&
        (0U < PolicyList.uiCount)) {
        iResult = 0;
    }
    else if (IPSEC_OK == eError) {
        eError = IPSEC_ERR_INTERNAL;
    }
    else {
        /* Preserve operation error. */
    }

    if (bInitiated) {
        (void)TerminateIpsecIke(pContext, Connection.pcName, &Control);
    }
    else {
        /* No SA was initiated. */
    }
    if (bCredentialsLoaded) {
        (void)ClearIpsecCredentials(pContext);
    }
    else {
        /* No VICI credential was loaded. */
    }
    if (bConnectionLoaded) {
        (void)RemoveIpsecConnection(pContext, Connection.pcName);
    }
    else {
        /* No connection was loaded. */
    }
    FreeIpsecXfrmPolicyList(&PolicyList);
    FreeIpsecXfrmStateList(&StateList);
    FreeIpsecChildSaList(&ChildList);
    FreeIpsecIkeSaList(&IkeList);
    DeinitializeIpsec(pContext);

    if (0 != iResult) {
        iResult = ReportIntegrationError("live IPsec workflow", eError);
    }
    else {
        (void)printf("live IPsec workflow passed\n");
    }
    return iResult;
}
