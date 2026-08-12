#include "app_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define APP_LOOP_TEST_COUNT 25U
#define APP_LOOP_TEST_REQID 77U

static bool gbConnectionLoaded = false;
static bool gbSaInstalled = false;
static uint32_t guiConnectionAddCount = 0U;
static uint32_t guiConnectionRemoveCount = 0U;
static uint32_t guiInitiateCount = 0U;
static uint32_t guiTerminateCount = 0U;
static uint32_t guiCredentialAddCount = 0U;

IpsecError_t ReadNativeAppSecret(
    const NativeAppConfig_t *pConfig,
    NativeAppSecret_t *pSecret)
{
    (void)pConfig;
    pSecret->pucData = malloc(4U);
    if (NULL == pSecret->pucData) {
        return IPSEC_ERR_NO_MEMORY;
    }
    else {
        (void)memcpy(pSecret->pucData, "test", 4U);
        pSecret->uiLength = 4U;
        return IPSEC_OK;
    }
}

void DestroyNativeAppSecret(NativeAppSecret_t *pSecret)
{
    if ((NULL != pSecret) && (NULL != pSecret->pucData)) {
        (void)memset(pSecret->pucData, 0, 4U);
        free(pSecret->pucData);
        pSecret->pucData = NULL;
        pSecret->uiLength = 0U;
    }
    else {
        /* No mock secret is allocated. */
    }
}

IpsecError_t AddIpsecConnection(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig)
{
    (void)pContext;
    (void)pConfig;
    if (gbConnectionLoaded || gbSaInstalled) {
        return IPSEC_ERR_INTERNAL;
    }
    else {
        gbConnectionLoaded = true;
        guiConnectionAddCount++;
        return IPSEC_OK;
    }
}

IpsecError_t RemoveIpsecConnection(
    IpsecContext_t *pContext,
    const char *pcName)
{
    (void)pContext;
    (void)pcName;
    if (!gbConnectionLoaded || gbSaInstalled) {
        return IPSEC_ERR_INTERNAL;
    }
    else {
        gbConnectionLoaded = false;
        guiConnectionRemoveCount++;
        return IPSEC_OK;
    }
}

IpsecError_t AddIpsecPsk(
    IpsecContext_t *pContext,
    const IpsecPsk_t *pPsk)
{
    (void)pContext;
    if ((NULL == pPsk) || (4U != pPsk->uiDataLength)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        guiCredentialAddCount++;
        return IPSEC_OK;
    }
}

IpsecError_t ClearIpsecCredentials(IpsecContext_t *pContext)
{
    (void)pContext;
    return IPSEC_OK;
}

IpsecError_t InitiateIpsecIke(
    IpsecContext_t *pContext,
    const char *pcConnectionName,
    const IpsecControlOptions_t *pOptions)
{
    (void)pContext;
    (void)pcConnectionName;
    (void)pOptions;
    if (!gbConnectionLoaded || gbSaInstalled) {
        return IPSEC_ERR_IKE_FAILED;
    }
    else {
        gbSaInstalled = true;
        guiInitiateCount++;
        return IPSEC_OK;
    }
}

IpsecError_t InitiateIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName,
    const IpsecControlOptions_t *pOptions)
{
    return InitiateIpsecIke(pContext, pcChildName, pOptions);
}

IpsecError_t WaitIpsecIkeEstablished(
    IpsecContext_t *pContext,
    const char *pcIkeName,
    uint32_t uiTimeoutMs)
{
    (void)pContext;
    (void)pcIkeName;
    (void)uiTimeoutMs;
    return gbSaInstalled ? IPSEC_OK : IPSEC_ERR_IKE_FAILED;
}

IpsecError_t WaitIpsecChildInstalled(
    IpsecContext_t *pContext,
    const char *pcChildName,
    uint32_t uiTimeoutMs)
{
    (void)pContext;
    (void)pcChildName;
    (void)uiTimeoutMs;
    return gbSaInstalled ? IPSEC_OK : IPSEC_ERR_CHILD_FAILED;
}

IpsecError_t TerminateIpsecIke(
    IpsecContext_t *pContext,
    const char *pcIkeName,
    const IpsecControlOptions_t *pOptions)
{
    (void)pContext;
    (void)pcIkeName;
    (void)pOptions;
    if (!gbSaInstalled) {
        return IPSEC_ERR_CONNECTION_NOT_FOUND;
    }
    else {
        gbSaInstalled = false;
        guiTerminateCount++;
        return IPSEC_OK;
    }
}

IpsecError_t GetIpsecIkeSas(
    IpsecContext_t *pContext,
    IpsecIkeSaList_t *pList)
{
    (void)pContext;
    (void)memset(pList, 0, sizeof(*pList));
    if (gbSaInstalled) {
        pList->pItems = calloc(1U, sizeof(*pList->pItems));
        if (NULL == pList->pItems) {
            return IPSEC_ERR_NO_MEMORY;
        }
        else {
            pList->uiCount = 1U;
            pList->pItems[0].bEstablished = true;
            (void)snprintf(pList->pItems[0].acName,
                           sizeof(pList->pItems[0].acName), "%s", "loop-ike");
        }
    }
    else {
        /* Return an empty VICI list after termination. */
    }
    return IPSEC_OK;
}

void FreeIpsecIkeSaList(IpsecIkeSaList_t *pList)
{
    free(pList->pItems);
    (void)memset(pList, 0, sizeof(*pList));
}

IpsecError_t GetIpsecChildSas(
    IpsecContext_t *pContext,
    IpsecChildSaList_t *pList)
{
    (void)pContext;
    (void)memset(pList, 0, sizeof(*pList));
    if (gbSaInstalled) {
        pList->pItems = calloc(1U, sizeof(*pList->pItems));
        if (NULL == pList->pItems) {
            return IPSEC_ERR_NO_MEMORY;
        }
        else {
            pList->uiCount = 1U;
            pList->pItems[0].uiReqid = APP_LOOP_TEST_REQID;
            (void)snprintf(pList->pItems[0].acName,
                           sizeof(pList->pItems[0].acName), "%s",
                           "loop-child");
            (void)snprintf(pList->pItems[0].acState,
                           sizeof(pList->pItems[0].acState), "%s",
                           "INSTALLED");
        }
    }
    else {
        /* Return an empty VICI list after termination. */
    }
    return IPSEC_OK;
}

void FreeIpsecChildSaList(IpsecChildSaList_t *pList)
{
    free(pList->pItems);
    (void)memset(pList, 0, sizeof(*pList));
}

IpsecError_t GetIpsecXfrmStates(
    IpsecContext_t *pContext,
    IpsecXfrmStateList_t *pList)
{
    (void)pContext;
    (void)memset(pList, 0, sizeof(*pList));
    if (gbSaInstalled) {
        pList->pItems = calloc(1U, sizeof(*pList->pItems));
        if (NULL == pList->pItems) {
            return IPSEC_ERR_NO_MEMORY;
        }
        else {
            pList->uiCount = 1U;
            pList->pItems[0].uiReqid = APP_LOOP_TEST_REQID;
        }
    }
    else {
        /* Return an empty kernel state list after termination. */
    }
    return IPSEC_OK;
}

void FreeIpsecXfrmStateList(IpsecXfrmStateList_t *pList)
{
    free(pList->pItems);
    (void)memset(pList, 0, sizeof(*pList));
}

IpsecError_t GetIpsecXfrmPolicies(
    IpsecContext_t *pContext,
    IpsecXfrmPolicyList_t *pList)
{
    (void)pContext;
    (void)memset(pList, 0, sizeof(*pList));
    if (gbSaInstalled) {
        pList->pItems = calloc(1U, sizeof(*pList->pItems));
        if (NULL == pList->pItems) {
            return IPSEC_ERR_NO_MEMORY;
        }
        else {
            pList->uiCount = 1U;
            pList->pItems[0].uiReqid = APP_LOOP_TEST_REQID;
        }
    }
    else {
        /* Return an empty kernel policy list after termination. */
    }
    return IPSEC_OK;
}

void FreeIpsecXfrmPolicyList(IpsecXfrmPolicyList_t *pList)
{
    free(pList->pItems);
    (void)memset(pList, 0, sizeof(*pList));
}

const char *GetIpsecErrorString(IpsecError_t eError)
{
    (void)eError;
    return "mock error";
}

int main(void)
{
    NativeAppConfig_t Config = {0};
    NativeAppRuntimeConfig_t Runtime = {0};
    NativeAppLoopOptions_t Options = {
        .uiCount = APP_LOOP_TEST_COUNT,
        .uiDelayMs = 0U
    };
    IpsecContext_t *pContext = (IpsecContext_t *)(uintptr_t)1U;
    IpsecError_t eError;

    Config.eRole = NATIVE_APP_ROLE_INITIATOR;
    Config.uiTimeoutMs = 1000U;
    (void)snprintf(Config.acConnectionName,
                   sizeof(Config.acConnectionName), "%s", "loop-ike");
    (void)snprintf(Config.acChildName,
                   sizeof(Config.acChildName), "%s", "loop-child");
    (void)snprintf(Config.acLocalId,
                   sizeof(Config.acLocalId), "%s", "side-a");
    (void)snprintf(Config.acRemoteId,
                   sizeof(Config.acRemoteId), "%s", "side-b");
    Runtime.Connection.pcName = Config.acConnectionName;
    Runtime.Connection.pcChildName = Config.acChildName;

    eError = RunNativeAppLoop(pContext, &Config, &Runtime, &Options);
    if ((IPSEC_OK != eError) || gbConnectionLoaded || gbSaInstalled ||
        (1U != guiCredentialAddCount) ||
        (APP_LOOP_TEST_COUNT != guiConnectionAddCount) ||
        (APP_LOOP_TEST_COUNT != guiConnectionRemoveCount) ||
        (APP_LOOP_TEST_COUNT != guiInitiateCount) ||
        (APP_LOOP_TEST_COUNT != guiTerminateCount)) {
        (void)fprintf(stderr, "application lifecycle loop test failed\n");
        return 1;
    }
    else {
        (void)printf("application lifecycle loop test passed: %" PRIu32
                     " iterations\n", APP_LOOP_TEST_COUNT);
        return 0;
    }
}
