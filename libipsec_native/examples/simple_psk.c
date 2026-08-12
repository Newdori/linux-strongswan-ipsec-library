#include "ipsec.h"

#include <stdio.h>
#include <string.h>

static void LogExample(
    IpsecLogLevel_t eLevel,
    const char *pcMessage,
    void *pvUserData)
{
    const char *pcLevel;

    (void)pvUserData;
    switch (eLevel) {
    case IPSEC_LOG_ERROR:
        pcLevel = "ERROR";
        break;
    case IPSEC_LOG_WARNING:
        pcLevel = "WARN";
        break;
    case IPSEC_LOG_INFO:
        pcLevel = "INFO";
        break;
    case IPSEC_LOG_DEBUG:
    default:
        pcLevel = "DEBUG";
        break;
    }
    (void)fprintf(stderr, "[%s] %s\n", pcLevel, pcMessage);
}

int main(void)
{
    static const char *const apcLocalAddresses[] = {"192.0.2.10"};
    static const char *const apcRemoteAddresses[] = {"192.0.2.20"};
    static const char *const apcIkeProposals[] = {
        "aes256-sha256-prfsha256-modp2048"
    };
    static const char *const apcEspProposals[] = {
        "aes256-sha256-noesn"
    };
    static const char *const apcLocalSelectors[] = {"192.0.2.10/32"};
    static const char *const apcRemoteSelectors[] = {"192.0.2.20/32"};
    static const char *const apcOwners[] = {"side-a", "side-b"};
    static const uint8_t aucPsk[] =
        "replace-this-example-with-a-secure-random-psk";
    IpsecContext_t *pContext = NULL;
    IpsecConfig_t Config;
    IpsecConnectionConfig_t Connection;
    IpsecPsk_t Psk;
    IpsecControlOptions_t Control;
    IpsecError_t eError;
    int32_t iExitCode = 1;

    memset(&Config, 0, sizeof(Config));
    Config.uiStructSize = sizeof(Config);
    Config.uiConnectTimeoutMs = 3000U;
    Config.uiCommandTimeoutMs = 15000U;
    Config.pLogCallback = LogExample;

    memset(&Connection, 0, sizeof(Connection));
    Connection.uiStructSize = sizeof(Connection);
    Connection.pcName = "vpn1";
    Connection.pcChildName = "vpn1-child";
    Connection.LocalAddresses.ppcItems = apcLocalAddresses;
    Connection.LocalAddresses.uiCount = 1U;
    Connection.RemoteAddresses.ppcItems = apcRemoteAddresses;
    Connection.RemoteAddresses.uiCount = 1U;
    Connection.eLocalAuth = IPSEC_AUTH_PSK;
    Connection.eRemoteAuth = IPSEC_AUTH_PSK;
    Connection.pcLocalId = "side-a";
    Connection.pcRemoteId = "side-b";
    Connection.IkeProposals.ppcItems = apcIkeProposals;
    Connection.IkeProposals.uiCount = 1U;
    Connection.EspProposals.ppcItems = apcEspProposals;
    Connection.EspProposals.uiCount = 1U;
    Connection.LocalTrafficSelectors.ppcItems = apcLocalSelectors;
    Connection.LocalTrafficSelectors.uiCount = 1U;
    Connection.RemoteTrafficSelectors.ppcItems = apcRemoteSelectors;
    Connection.RemoteTrafficSelectors.uiCount = 1U;
    Connection.eMode = IPSEC_MODE_TRANSPORT;
    Connection.eEsn = IPSEC_ESN_DISABLED;
    Connection.bEnableFragmentation = true;
    Connection.uiDpdDelayMs = 30000U;
    Connection.uiDpdTimeoutMs = 120000U;
    Connection.ullIkeRekeyTimeMs = 14400000U;
    Connection.ullIkeLifetimeMs = 18000000U;
    Connection.ullChildRekeyTimeMs = 3600000U;
    Connection.ullChildLifetimeMs = 4200000U;

    memset(&Psk, 0, sizeof(Psk));
    Psk.uiStructSize = sizeof(Psk);
    Psk.pcId = "vpn1-psk";
    Psk.pucData = aucPsk;
    Psk.uiDataLength = sizeof(aucPsk) - 1U;
    Psk.Owners.ppcItems = apcOwners;
    Psk.Owners.uiCount = 2U;

    memset(&Control, 0, sizeof(Control));
    Control.uiStructSize = sizeof(Control);
    Control.eMode = IPSEC_CONTROL_WAIT;
    Control.uiTimeoutMs = 10000U;

    eError = InitializeIpsec(&pContext, &Config);
    if (IPSEC_OK == eError) {
        eError = AddIpsecConnection(pContext, &Connection);
    }
    else {
        /* Initialization failed. */
    }
    if (IPSEC_OK == eError) {
        eError = AddIpsecPsk(pContext, &Psk);
    }
    else {
        /* Preserve previous error. */
    }
    if (IPSEC_OK == eError) {
        eError = InitiateIpsecChild(pContext, Connection.pcChildName,
                                    &Control);
    }
    else {
        /* Preserve previous error. */
    }
    if (IPSEC_OK == eError) {
        eError = WaitIpsecChildInstalled(pContext, Connection.pcChildName,
                                         10000U);
    }
    else {
        /* Preserve previous error. */
    }
    if (IPSEC_OK == eError) {
        iExitCode = 0;
    }
    else {
        (void)fprintf(stderr, "IPsec error: %s\n",
                      GetIpsecErrorString(eError));
    }

    DeinitializeIpsec(pContext);
    return iExitCode;
}
