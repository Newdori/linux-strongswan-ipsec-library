#include "app_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char *GetNativeAppMode(IpsecMode_t eMode)
{
    const char *pcMode;

    switch (eMode) {
    case IPSEC_MODE_TUNNEL:
        pcMode = "tunnel";
        break;
    case IPSEC_MODE_TRANSPORT:
        pcMode = "transport";
        break;
    case IPSEC_MODE_BEET:
        pcMode = "beet";
        break;
    default:
        pcMode = "unknown";
        break;
    }
    return pcMode;
}

static const char *GetNativeAppDirection(IpsecXfrmDirection_t eDirection)
{
    const char *pcDirection;

    switch (eDirection) {
    case IPSEC_XFRM_DIRECTION_IN:
        pcDirection = "in";
        break;
    case IPSEC_XFRM_DIRECTION_OUT:
        pcDirection = "out";
        break;
    case IPSEC_XFRM_DIRECTION_FORWARD:
        pcDirection = "fwd";
        break;
    default:
        pcDirection = "unknown";
        break;
    }
    return pcDirection;
}

static IpsecError_t ShowNativeAppDaemon(IpsecContext_t *pContext)
{
    IpsecDaemonStatus_t Status = {0};
    IpsecError_t eError = GetIpsecDaemonStatus(pContext, &Status);

    if (IPSEC_OK == eError) {
        (void)printf("[daemon]\nname=%s version=%s system=%s %s machine=%s\n"
                     "uptime_seconds=%" PRIu64 " workers=%" PRIu32
                     " idle=%" PRIu32 " ike_total=%" PRIu32
                     " half_open=%" PRIu32 "\n",
                     Status.acDaemon, Status.acVersion, Status.acSystemName,
                     Status.acSystemRelease, Status.acMachine,
                     Status.ullUptimeSeconds, Status.uiWorkerTotal,
                     Status.uiWorkerIdle, Status.uiIkeSaTotal,
                     Status.uiIkeSaHalfOpen);
    }
    else {
        /* The caller reports the structured error. */
    }
    return eError;
}

static IpsecError_t ShowNativeAppConnections(IpsecContext_t *pContext)
{
    IpsecConnectionList_t List = {0};
    IpsecError_t eError = GetIpsecConnections(pContext, &List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[connections] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecConnectionInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("name=%s local=%s remote=%s local_id=%s "
                         "remote_id=%s children=%s\n",
                         pItem->acName, pItem->acLocalAddresses,
                         pItem->acRemoteAddresses, pItem->acLocalId,
                         pItem->acRemoteId, pItem->acChildNames);
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecConnectionList(&List);
    return eError;
}

static IpsecError_t ShowNativeAppIkeSas(IpsecContext_t *pContext)
{
    IpsecIkeSaList_t List = {0};
    IpsecError_t eError = GetIpsecIkeSas(pContext, &List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[ike] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecIkeSaInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("name=%s state=%s established=%s initiator=%s "
                         "local=%s remote=%s local_id=%s remote_id=%s "
                         "proposal=%s nat_local=%s nat_remote=%s\n",
                         pItem->acName, pItem->acState,
                         pItem->bEstablished ? "yes" : "no",
                         pItem->bInitiator ? "yes" : "no",
                         pItem->acLocalAddress, pItem->acRemoteAddress,
                         pItem->acLocalId, pItem->acRemoteId,
                         pItem->acProposal,
                         pItem->bNatLocal ? "yes" : "no",
                         pItem->bNatRemote ? "yes" : "no");
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecIkeSaList(&List);
    return eError;
}

static IpsecError_t ShowNativeAppChildSas(IpsecContext_t *pContext)
{
    IpsecChildSaList_t List = {0};
    IpsecError_t eError = GetIpsecChildSas(pContext, &List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[child] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecChildSaInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("ike=%s name=%s state=%s reqid=%" PRIu32
                         " spi_in=0x%08" PRIx32 " spi_out=0x%08" PRIx32
                         " mode=%s esn=%s udp=%s proposal=%s "
                         "local_ts=%s remote_ts=%s bytes_in=%" PRIu64
                         " bytes_out=%" PRIu64 " packets_in=%" PRIu64
                         " packets_out=%" PRIu64 "\n",
                         pItem->acIkeName, pItem->acName, pItem->acState,
                         pItem->uiReqid, pItem->uiInboundSpi,
                         pItem->uiOutboundSpi, GetNativeAppMode(pItem->eMode),
                         pItem->bEsn ? "yes" : "no",
                         pItem->bUdpEncapsulation ? "yes" : "no",
                         pItem->acProposal, pItem->acLocalTrafficSelectors,
                         pItem->acRemoteTrafficSelectors, pItem->ullBytesIn,
                         pItem->ullBytesOut, pItem->ullPacketsIn,
                         pItem->ullPacketsOut);
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecChildSaList(&List);
    return eError;
}

static IpsecError_t ShowNativeAppAlgorithms(IpsecContext_t *pContext)
{
    IpsecAlgorithmList_t List = {0};
    IpsecError_t eError = GetIpsecAlgorithms(pContext, &List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[algorithms] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            (void)printf("type=%s name=%s plugin=%s\n",
                         List.pItems[uiIndex].acType,
                         List.pItems[uiIndex].acName,
                         List.pItems[uiIndex].acPlugin);
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecAlgorithmList(&List);
    return eError;
}

static IpsecError_t ShowNativeAppXfrmStates(IpsecContext_t *pContext)
{
    IpsecXfrmStateList_t List = {0};
    IpsecError_t eError = GetIpsecXfrmStates(pContext, &List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[xfrm-state] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecXfrmStateInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("src=%s dst=%s proto=%" PRIu32
                         " spi=0x%08" PRIx32 " reqid=%" PRIu32
                         " mode=%s enc=%s auth=%s aead=%s esn=%s "
                         "replay=%" PRIu32 " packets=%" PRIu64
                         " bytes=%" PRIu64 "\n",
                         pItem->acSource, pItem->acDestination,
                         pItem->uiProtocol, pItem->uiSpi, pItem->uiReqid,
                         GetNativeAppMode(pItem->eMode),
                         pItem->acEncryptionAlgorithm,
                         pItem->acIntegrityAlgorithm,
                         pItem->acAeadAlgorithm,
                         pItem->bEsn ? "yes" : "no",
                         pItem->uiReplayWindow, pItem->ullPacketCount,
                         pItem->ullByteCount);
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecXfrmStateList(&List);
    return eError;
}

static IpsecError_t ShowNativeAppXfrmPolicies(IpsecContext_t *pContext)
{
    IpsecXfrmPolicyList_t List = {0};
    IpsecError_t eError = GetIpsecXfrmPolicies(pContext, &List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[xfrm-policy] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecXfrmPolicyInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("dir=%s src=%s/%" PRIu8 " dst=%s/%" PRIu8
                         " priority=%" PRIu32 " index=%" PRIu32
                         " reqid=%" PRIu32 " mode=%s tmpl_src=%s "
                         "tmpl_dst=%s proto=%" PRIu32 "\n",
                         GetNativeAppDirection(pItem->eDirection),
                         pItem->acSourceSelector,
                         pItem->ucSourcePrefixLength,
                         pItem->acDestinationSelector,
                         pItem->ucDestinationPrefixLength,
                         pItem->uiPriority, pItem->uiIndex, pItem->uiReqid,
                         GetNativeAppMode(pItem->eMode),
                         pItem->acTemplateSource,
                         pItem->acTemplateDestination, pItem->uiProtocol);
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecXfrmPolicyList(&List);
    return eError;
}

static IpsecError_t ShowNativeAppXfrmStatistics(void)
{
    IpsecXfrmStatistics_t Statistics = {0};
    IpsecError_t eError = GetIpsecXfrmStatistics(&Statistics);

    if (IPSEC_OK == eError) {
        (void)printf("[xfrm-stat]\n"
                     "in_error=%" PRIu64 " in_buffer_error=%" PRIu64
                     " in_header_error=%" PRIu64
                     " in_no_states=%" PRIu64
                     " in_state_proto_error=%" PRIu64
                     " in_state_mode_error=%" PRIu64
                     " in_state_seq_error=%" PRIu64
                     " in_state_expired=%" PRIu64 "\n"
                     "out_error=%" PRIu64
                     " out_bundle_gen_error=%" PRIu64
                     " out_bundle_check_error=%" PRIu64
                     " out_no_states=%" PRIu64
                     " out_state_proto_error=%" PRIu64
                     " out_state_mode_error=%" PRIu64
                     " out_state_seq_error=%" PRIu64
                     " out_state_expired=%" PRIu64
                     " out_policy_block=%" PRIu64 "\n",
                     Statistics.ullInError, Statistics.ullInBufferError,
                     Statistics.ullInHeaderError, Statistics.ullInNoStates,
                     Statistics.ullInStateProtocolError,
                     Statistics.ullInStateModeError,
                     Statistics.ullInStateSequenceError,
                     Statistics.ullInStateExpired, Statistics.ullOutError,
                     Statistics.ullOutBundleGenerationError,
                     Statistics.ullOutBundleCheckError,
                     Statistics.ullOutNoStates,
                     Statistics.ullOutStateProtocolError,
                     Statistics.ullOutStateModeError,
                     Statistics.ullOutStateSequenceError,
                     Statistics.ullOutStateExpired,
                     Statistics.ullOutPolicyBlock);
    }
    else {
        /* The caller reports the structured error. */
    }
    return eError;
}

static IpsecError_t ShowNativeAppInterfaces(void)
{
    IpsecInterfaceList_t List = {0};
    IpsecError_t eError = GetIpsecInterfaces(&List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[interfaces] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecInterfaceInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("ifindex=%" PRIu32 " name=%s up=%s running=%s "
                         "carrier=%s mtu=%" PRIu32 " mac=%s flags=0x%08"
                         PRIx32 "\n",
                         pItem->uiIndex, pItem->acName,
                         pItem->bUp ? "yes" : "no",
                         pItem->bRunning ? "yes" : "no",
                         pItem->bCarrier ? "yes" : "no", pItem->uiMtu,
                         pItem->acMacAddress, pItem->uiFlags);
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecInterfaceList(&List);
    return eError;
}

static IpsecError_t ShowNativeAppAddresses(void)
{
    IpsecAddressList_t List = {0};
    IpsecError_t eError = GetIpsecAddresses(&List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[addresses] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecAddressInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("ifindex=%" PRIu32 " interface=%s address=%s/%"
                         PRIu8 " family=%" PRIu32 " scope=%" PRIu8 "\n",
                         pItem->uiInterfaceIndex, pItem->acInterfaceName,
                         pItem->acAddress, pItem->ucPrefixLength,
                         (uint32_t)pItem->eFamily, pItem->ucScope);
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecAddressList(&List);
    return eError;
}

static IpsecError_t ShowNativeAppRoutes(void)
{
    IpsecRouteList_t List = {0};
    IpsecError_t eError = GetIpsecRoutes(&List);
    uint32_t uiIndex;

    if (IPSEC_OK == eError) {
        (void)printf("[routes] count=%" PRIu32 "\n", List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecRouteInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("dst=%s/%" PRIu8 " gateway=%s source=%s "
                         "ifindex=%" PRIu32 " interface=%s metric=%" PRIu32
                         " table=%" PRIu32 " protocol=%" PRIu8
                         " scope=%" PRIu8 "\n",
                         pItem->acDestination, pItem->ucPrefixLength,
                         pItem->acGateway, pItem->acSource,
                         pItem->uiInterfaceIndex, pItem->acInterfaceName,
                         pItem->uiMetric, pItem->uiTable, pItem->ucProtocol,
                         pItem->ucScope);
        }
    }
    else {
        /* The caller reports the structured error. */
    }
    FreeIpsecRouteList(&List);
    return eError;
}

static void RecordNativeAppStatusError(
    const char *pcSection,
    IpsecError_t eError,
    IpsecError_t *peFirstError)
{
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "status %s failed: %s\n", pcSection,
                      GetIpsecErrorString(eError));
        if (IPSEC_OK == *peFirstError) {
            *peFirstError = eError;
        }
        else {
            /* Preserve the first status error. */
        }
    }
    else {
        /* This section completed successfully. */
    }
}

IpsecError_t ShowNativeAppStatus(
    IpsecContext_t *pContext,
    const char *pcScope)
{
    IpsecError_t eFirstError = IPSEC_OK;
    bool bAll;
    bool bKnown;

    if ((NULL == pContext) || (NULL == pcScope)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        bAll = (0 == strcmp("all", pcScope));
    }
    bKnown = bAll || (0 == strcmp("daemon", pcScope)) ||
             (0 == strcmp("connections", pcScope)) ||
             (0 == strcmp("ike", pcScope)) ||
             (0 == strcmp("child", pcScope)) ||
             (0 == strcmp("algorithms", pcScope)) ||
             (0 == strcmp("xfrm-state", pcScope)) ||
             (0 == strcmp("xfrm-policy", pcScope)) ||
             (0 == strcmp("xfrm-stat", pcScope)) ||
             (0 == strcmp("interfaces", pcScope)) ||
             (0 == strcmp("addresses", pcScope)) ||
             (0 == strcmp("routes", pcScope));
    if (!bKnown) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        /* Run the requested section or every section. */
    }

    if (bAll || (0 == strcmp("daemon", pcScope))) {
        RecordNativeAppStatusError("daemon", ShowNativeAppDaemon(pContext),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("connections", pcScope))) {
        RecordNativeAppStatusError("connections",
                                   ShowNativeAppConnections(pContext),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("ike", pcScope))) {
        RecordNativeAppStatusError("ike", ShowNativeAppIkeSas(pContext),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("child", pcScope))) {
        RecordNativeAppStatusError("child", ShowNativeAppChildSas(pContext),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("algorithms", pcScope))) {
        RecordNativeAppStatusError("algorithms",
                                   ShowNativeAppAlgorithms(pContext),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("xfrm-state", pcScope))) {
        RecordNativeAppStatusError("xfrm-state",
                                   ShowNativeAppXfrmStates(pContext),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("xfrm-policy", pcScope))) {
        RecordNativeAppStatusError("xfrm-policy",
                                   ShowNativeAppXfrmPolicies(pContext),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("xfrm-stat", pcScope))) {
        RecordNativeAppStatusError("xfrm-stat",
                                   ShowNativeAppXfrmStatistics(),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("interfaces", pcScope))) {
        RecordNativeAppStatusError("interfaces",
                                   ShowNativeAppInterfaces(), &eFirstError);
    }
    if (bAll || (0 == strcmp("addresses", pcScope))) {
        RecordNativeAppStatusError("addresses", ShowNativeAppAddresses(),
                                   &eFirstError);
    }
    if (bAll || (0 == strcmp("routes", pcScope))) {
        RecordNativeAppStatusError("routes", ShowNativeAppRoutes(),
                                   &eFirstError);
    }
    return eFirstError;
}
