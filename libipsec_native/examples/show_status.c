#include "ipsec.h"

#include <inttypes.h>
#include <stdio.h>

int main(void)
{
    IpsecContext_t *pContext = NULL;
    IpsecConfig_t Config = {
        .uiStructSize = sizeof(IpsecConfig_t)
    };
    IpsecDaemonStatus_t Status;
    IpsecIkeSaList_t IkeList = {0};
    IpsecChildSaList_t ChildList = {0};
    IpsecError_t eError;
    uint32_t uiIndex;
    int32_t iExitCode = 1;

    eError = InitializeIpsec(&pContext, &Config);
    if (IPSEC_OK == eError) {
        eError = GetIpsecDaemonStatus(pContext, &Status);
    }
    else {
        /* Initialization failed. */
    }
    if (IPSEC_OK == eError) {
        (void)printf("%s %s on %s %s\n", Status.acDaemon,
                     Status.acVersion, Status.acSystemName,
                     Status.acSystemRelease);
        eError = GetIpsecIkeSas(pContext, &IkeList);
    }
    else {
        /* Preserve previous error. */
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < IkeList.uiCount; uiIndex++) {
            (void)printf("IKE %s state=%s id=%" PRIu64 "\n",
                         IkeList.pItems[uiIndex].acName,
                         IkeList.pItems[uiIndex].acState,
                         IkeList.pItems[uiIndex].ullUniqueId);
        }
        eError = GetIpsecChildSas(pContext, &ChildList);
    }
    else {
        /* Preserve previous error. */
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < ChildList.uiCount; uiIndex++) {
            (void)printf("CHILD %s state=%s reqid=%u\n",
                         ChildList.pItems[uiIndex].acName,
                         ChildList.pItems[uiIndex].acState,
                         ChildList.pItems[uiIndex].uiReqid);
        }
        iExitCode = 0;
    }
    else {
        (void)fprintf(stderr, "IPsec error: %s\n",
                      GetIpsecErrorString(eError));
    }

    FreeIpsecChildSaList(&ChildList);
    FreeIpsecIkeSaList(&IkeList);
    DeinitializeIpsec(pContext);
    return iExitCode;
}
