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
        (void)printf("[DAEMON]\n"
                     "  Name             : %s\n"
                     "  Version          : %s\n"
                     "  System           : %s %s (%s)\n"
                     "  Uptime           : %" PRIu64 " seconds\n"
                     "  Workers          : total=%" PRIu32
                     ", idle=%" PRIu32 "\n"
                     "  IKE SAs          : total=%" PRIu32
                     ", half-open=%" PRIu32 "\n",
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
        (void)printf("[CONNECTIONS]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecConnectionInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("\n[CONNECTION %" PRIu32 "/%" PRIu32 "]\n"
                         "  Name             : %s\n"
                         "  Local Address    : %s\n"
                         "  Remote Address   : %s\n"
                         "  Local ID         : %s\n"
                         "  Remote ID        : %s\n"
                         "  Children         : %s\n",
                         uiIndex + 1U, List.uiCount,
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
        (void)printf("[IKE SAs]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecIkeSaInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("\n[IKE SA %" PRIu32 "/%" PRIu32 "]\n"
                         "  Name             : %s\n"
                         "  State            : %s\n"
                         "  Established      : %s\n"
                         "  Role             : %s\n"
                         "  Local            : %s (%s)\n"
                         "  Remote           : %s (%s)\n"
                         "  Proposal         : %s\n"
                         "  NAT              : local=%s, remote=%s\n",
                         uiIndex + 1U, List.uiCount,
                         pItem->acName, pItem->acState,
                         pItem->bEstablished ? "yes" : "no",
                         pItem->bInitiator ? "initiator" : "responder",
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
        (void)printf("[CHILD SAs]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecChildSaInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("\n[CHILD SA %" PRIu32 "/%" PRIu32 "]\n"
                         "  IKE Name         : %s\n"
                         "  Name             : %s\n"
                         "  State            : %s\n"
                         "  Mode             : %s\n"
                         "  ReqID            : %" PRIu32 "\n"
                         "  Inbound SPI      : 0x%08" PRIx32 "\n"
                         "  Outbound SPI     : 0x%08" PRIx32 "\n"
                         "  Proposal         : %s\n"
                         "  ESN              : %s\n"
                         "  UDP Encapsulation: %s\n"
                         "  Local TS         : %s\n"
                         "  Remote TS        : %s\n"
                         "  Inbound Traffic  : %" PRIu64
                         " packets, %" PRIu64 " bytes\n"
                         "  Outbound Traffic : %" PRIu64
                         " packets, %" PRIu64 " bytes\n",
                         uiIndex + 1U, List.uiCount,
                         pItem->acIkeName, pItem->acName, pItem->acState,
                         GetNativeAppMode(pItem->eMode), pItem->uiReqid,
                         pItem->uiInboundSpi, pItem->uiOutboundSpi,
                         pItem->acProposal, pItem->bEsn ? "yes" : "no",
                         pItem->bUdpEncapsulation ? "yes" : "no",
                         pItem->acLocalTrafficSelectors,
                         pItem->acRemoteTrafficSelectors,
                         pItem->ullPacketsIn, pItem->ullBytesIn,
                         pItem->ullPacketsOut, pItem->ullBytesOut);
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
        (void)printf("[ALGORITHMS]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            (void)printf("  %3" PRIu32 ". %-16s %-32s %s\n",
                         uiIndex + 1U,
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
        (void)printf("[XFRM STATES]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecXfrmStateInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("\n[XFRM STATE %" PRIu32 "/%" PRIu32 "]\n"
                         "  Source           : %s\n"
                         "  Destination      : %s\n"
                         "  Protocol         : %" PRIu32 "\n"
                         "  SPI              : 0x%08" PRIx32 "\n"
                         "  ReqID            : %" PRIu32 "\n"
                         "  Mode             : %s\n"
                         "  Encryption       : %s\n"
                         "  Integrity        : %s\n"
                         "  AEAD             : %s\n"
                         "  ESN              : %s\n"
                         "  Replay Window    : %" PRIu32 "\n"
                         "  Traffic          : %" PRIu64
                         " packets, %" PRIu64 " bytes\n",
                         uiIndex + 1U, List.uiCount,
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
        (void)printf("[XFRM POLICIES]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecXfrmPolicyInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("\n[XFRM POLICY %" PRIu32 "/%" PRIu32 "]\n"
                         "  Direction        : %s\n"
                         "  Source Selector  : %s/%" PRIu8 "\n"
                         "  Destination      : %s/%" PRIu8 "\n"
                         "  Priority         : %" PRIu32 "\n"
                         "  Index            : %" PRIu32 "\n"
                         "  ReqID            : %" PRIu32 "\n"
                         "  Mode             : %s\n"
                         "  Template Source  : %s\n"
                         "  Template Dest.   : %s\n"
                         "  Protocol         : %" PRIu32 "\n",
                         uiIndex + 1U, List.uiCount,
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
        (void)printf("[XFRM STATISTICS]\n"
                     "  In Error         : %" PRIu64 "\n"
                     "  In Buffer Error  : %" PRIu64 "\n"
                     "  In Header Error  : %" PRIu64 "\n"
                     "  In No States     : %" PRIu64 "\n"
                     "  In Proto Error   : %" PRIu64 "\n"
                     "  In Mode Error    : %" PRIu64 "\n"
                     "  In Seq Error     : %" PRIu64 "\n"
                     "  In Expired       : %" PRIu64 "\n"
                     "  Out Error        : %" PRIu64 "\n"
                     "  Out Bundle Gen.  : %" PRIu64 "\n"
                     "  Out Bundle Check : %" PRIu64 "\n"
                     "  Out No States    : %" PRIu64 "\n"
                     "  Out Proto Error  : %" PRIu64 "\n"
                     "  Out Mode Error   : %" PRIu64 "\n"
                     "  Out Seq Error    : %" PRIu64 "\n"
                     "  Out Expired      : %" PRIu64 "\n"
                     "  Out Policy Block : %" PRIu64 "\n",
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
        (void)printf("[INTERFACES]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecInterfaceInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("\n[INTERFACE %" PRIu32 "/%" PRIu32 "]\n"
                         "  Index            : %" PRIu32 "\n"
                         "  Name             : %s\n"
                         "  State            : up=%s, running=%s, carrier=%s\n"
                         "  MTU              : %" PRIu32 "\n"
                         "  MAC Address      : %s\n"
                         "  Flags            : 0x%08" PRIx32 "\n",
                         uiIndex + 1U, List.uiCount,
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
        (void)printf("[ADDRESSES]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecAddressInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("  %3" PRIu32 ". %-16s %s/%" PRIu8
                         "  family=%" PRIu32 " scope=%" PRIu8
                         " ifindex=%" PRIu32 "\n",
                         uiIndex + 1U,
                         pItem->acInterfaceName, pItem->acAddress,
                         pItem->ucPrefixLength,
                         (uint32_t)pItem->eFamily, pItem->ucScope,
                         pItem->uiInterfaceIndex);
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
        (void)printf("[ROUTES]\n  Count            : %" PRIu32 "\n",
                     List.uiCount);
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecRouteInfo_t *pItem = &List.pItems[uiIndex];

            (void)printf("\n[ROUTE %" PRIu32 "/%" PRIu32 "]\n"
                         "  Destination      : %s/%" PRIu8 "\n"
                         "  Gateway          : %s\n"
                         "  Source           : %s\n"
                         "  Interface        : %s (%" PRIu32 ")\n"
                         "  Metric           : %" PRIu32 "\n"
                         "  Table            : %" PRIu32 "\n"
                         "  Protocol         : %" PRIu8 "\n"
                         "  Scope            : %" PRIu8 "\n",
                         uiIndex + 1U, List.uiCount,
                         pItem->acDestination, pItem->ucPrefixLength,
                         pItem->acGateway, pItem->acSource,
                         pItem->acInterfaceName, pItem->uiInterfaceIndex,
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

static void RecordNativeAppShowError(
    const char *pcSection,
    IpsecError_t eError,
    IpsecError_t *peFirstError)
{
    if (IPSEC_OK != eError) {
        (void)printf("[%s]\n"
                     "  Status           : unavailable\n"
                     "  Error            : %s\n",
                     pcSection, GetIpsecErrorString(eError));
        if (IPSEC_OK == *peFirstError) {
            *peFirstError = eError;
        }
        else {
            /* Preserve the first show error. */
        }
    }
    else {
        /* This section completed successfully. */
    }
}

IpsecError_t ShowNativeAppInformation(
    IpsecContext_t *pContext,
    const char *pcScope)
{
    IpsecError_t eFirstError = IPSEC_OK;
    bool bAll;
    bool bSummary;
    bool bXfrm;
    bool bNetwork;
    bool bKnown;

    if ((NULL == pContext) || (NULL == pcScope)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        bAll = (0 == strcmp("all", pcScope));
        bSummary = (0 == strcmp("summary", pcScope));
        bXfrm = (0 == strcmp("xfrm", pcScope));
        bNetwork = (0 == strcmp("network", pcScope));
    }
    bKnown = bAll || bSummary || bXfrm || bNetwork ||
             (0 == strcmp("daemon", pcScope)) ||
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

    if (bAll || bSummary || (0 == strcmp("daemon", pcScope))) {
        RecordNativeAppShowError("DAEMON", ShowNativeAppDaemon(pContext),
                                 &eFirstError);
    }
    if (bAll || bSummary || (0 == strcmp("connections", pcScope))) {
        RecordNativeAppShowError("CONNECTIONS",
                                 ShowNativeAppConnections(pContext),
                                 &eFirstError);
    }
    if (bAll || bSummary || (0 == strcmp("ike", pcScope))) {
        RecordNativeAppShowError("IKE SAs", ShowNativeAppIkeSas(pContext),
                                 &eFirstError);
    }
    if (bAll || bSummary || (0 == strcmp("child", pcScope))) {
        RecordNativeAppShowError("CHILD SAs",
                                 ShowNativeAppChildSas(pContext),
                                 &eFirstError);
    }
    if (bAll || (0 == strcmp("algorithms", pcScope))) {
        RecordNativeAppShowError("ALGORITHMS",
                                 ShowNativeAppAlgorithms(pContext),
                                 &eFirstError);
    }
    if (bAll || bXfrm || (0 == strcmp("xfrm-state", pcScope))) {
        RecordNativeAppShowError("XFRM STATES",
                                 ShowNativeAppXfrmStates(pContext),
                                 &eFirstError);
    }
    if (bAll || bXfrm || (0 == strcmp("xfrm-policy", pcScope))) {
        RecordNativeAppShowError("XFRM POLICIES",
                                 ShowNativeAppXfrmPolicies(pContext),
                                 &eFirstError);
    }
    if (bAll || bXfrm || (0 == strcmp("xfrm-stat", pcScope))) {
        RecordNativeAppShowError("XFRM STATISTICS",
                                 ShowNativeAppXfrmStatistics(),
                                 &eFirstError);
    }
    if (bAll || bNetwork || (0 == strcmp("interfaces", pcScope))) {
        RecordNativeAppShowError("INTERFACES", ShowNativeAppInterfaces(),
                                 &eFirstError);
    }
    if (bAll || bNetwork || (0 == strcmp("addresses", pcScope))) {
        RecordNativeAppShowError("ADDRESSES", ShowNativeAppAddresses(),
                                 &eFirstError);
    }
    if (bAll || bNetwork || (0 == strcmp("routes", pcScope))) {
        RecordNativeAppShowError("ROUTES", ShowNativeAppRoutes(),
                                 &eFirstError);
    }
    return eFirstError;
}
