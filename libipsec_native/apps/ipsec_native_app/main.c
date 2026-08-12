#include "app_internal.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct NativeAppArguments {
    const char *pcConfigPath;
    const char *pcCommand;
    const char *pcStatusScope;
    NativeAppLoopOptions_t Loop;
    bool bClearCredentials;
    bool bVerbose;
    bool bHelp;
} NativeAppArguments_t;

static void PrintNativeAppUsage(const char *pcProgram)
{
    (void)printf(
        "Usage: %s --config FILE COMMAND [OPTIONS]\n"
        "\n"
        "Commands:\n"
        "  check                 validate config and VICI connectivity\n"
        "  load                  load connection and PSK\n"
        "  unload                unload connection definition\n"
        "  up                    load and establish IKE/CHILD SA\n"
        "  down                  terminate SA and unload connection\n"
        "  rekey-ike             rekey the configured IKE SA\n"
        "  rekey-child           rekey the configured CHILD SA\n"
        "  status [SCOPE]        show structured Native status\n"
        "  loop                  repeatedly establish, verify and remove SA\n"
        "  clear-credentials     clear all VICI shared-secret credentials\n"
        "\n"
        "Status scopes:\n"
        "  all, daemon, connections, ike, child, algorithms, xfrm-state,\n"
        "  xfrm-policy, xfrm-stat, interfaces, addresses, routes\n"
        "\n"
        "Loop options:\n"
        "  --count N             iterations (default: 10)\n"
        "  --delay-ms N          delay between iterations (default: 1000)\n"
        "  --continue-on-error   continue after a failed iteration\n"
        "\n"
        "Other options:\n"
        "  --clear-credentials   clear charon's global VICI credential set\n"
        "  --verbose             enable library diagnostic logging\n"
        "  --help                show this help\n",
        pcProgram);
}

static bool ParseNativeAppNumber(
    const char *pcText,
    uint32_t *puiValue)
{
    char *pcEnd = NULL;
    uint64_t ullValue;

    errno = 0;
    ullValue = strtoull(pcText, &pcEnd, 10);
    if ((0 != errno) || (pcEnd == pcText) || ('\0' != *pcEnd) ||
        (UINT32_MAX < ullValue)) {
        return false;
    }
    else {
        *puiValue = (uint32_t)ullValue;
        return true;
    }
}

static bool IsNativeAppCommand(const char *pcText)
{
    return (0 == strcmp("check", pcText)) ||
           (0 == strcmp("load", pcText)) ||
           (0 == strcmp("unload", pcText)) ||
           (0 == strcmp("up", pcText)) ||
           (0 == strcmp("down", pcText)) ||
           (0 == strcmp("rekey-ike", pcText)) ||
           (0 == strcmp("rekey-child", pcText)) ||
           (0 == strcmp("status", pcText)) ||
           (0 == strcmp("loop", pcText)) ||
           (0 == strcmp("clear-credentials", pcText));
}

static bool ParseNativeAppArguments(
    int32_t iArgumentCount,
    char **ppcArguments,
    NativeAppArguments_t *pArguments)
{
    int32_t iIndex;
    bool bParsed = true;

    (void)memset(pArguments, 0, sizeof(*pArguments));
    pArguments->pcStatusScope = "all";
    pArguments->Loop.uiCount = 10U;
    pArguments->Loop.uiDelayMs = 1000U;
    for (iIndex = 1; (iIndex < iArgumentCount) && bParsed; iIndex++) {
        const char *pcArgument = ppcArguments[iIndex];

        if (0 == strcmp("--config", pcArgument)) {
            if ((iIndex + 1) < iArgumentCount) {
                iIndex++;
                pArguments->pcConfigPath = ppcArguments[iIndex];
            }
            else {
                bParsed = false;
            }
        }
        else if (0 == strcmp("--count", pcArgument)) {
            if (((iIndex + 1) < iArgumentCount) &&
                ParseNativeAppNumber(ppcArguments[iIndex + 1],
                                     &pArguments->Loop.uiCount) &&
                (0U < pArguments->Loop.uiCount)) {
                iIndex++;
            }
            else {
                bParsed = false;
            }
        }
        else if (0 == strcmp("--delay-ms", pcArgument)) {
            if (((iIndex + 1) < iArgumentCount) &&
                ParseNativeAppNumber(ppcArguments[iIndex + 1],
                                     &pArguments->Loop.uiDelayMs)) {
                iIndex++;
            }
            else {
                bParsed = false;
            }
        }
        else if (0 == strcmp("--continue-on-error", pcArgument)) {
            pArguments->Loop.bContinueOnError = true;
        }
        else if (0 == strcmp("--clear-credentials", pcArgument)) {
            pArguments->bClearCredentials = true;
            pArguments->Loop.bClearCredentials = true;
        }
        else if (0 == strcmp("--verbose", pcArgument)) {
            pArguments->bVerbose = true;
        }
        else if ((0 == strcmp("--help", pcArgument)) ||
                 (0 == strcmp("-h", pcArgument))) {
            pArguments->bHelp = true;
        }
        else if ((0 == strcmp("--status", pcArgument)) &&
                 (NULL == pArguments->pcCommand)) {
            pArguments->pcCommand = "status";
        }
        else if ((0 == strcmp("--loop", pcArgument)) &&
                 (NULL == pArguments->pcCommand)) {
            pArguments->pcCommand = "loop";
        }
        else if ((NULL == pArguments->pcCommand) &&
                 IsNativeAppCommand(pcArgument)) {
            pArguments->pcCommand = pcArgument;
        }
        else if ((NULL != pArguments->pcCommand) &&
                 (0 == strcmp("status", pArguments->pcCommand)) &&
                 (0 == strcmp("all", pArguments->pcStatusScope))) {
            pArguments->pcStatusScope = pcArgument;
        }
        else {
            bParsed = false;
        }
    }
    if (!pArguments->bHelp &&
        ((NULL == pArguments->pcConfigPath) ||
         (NULL == pArguments->pcCommand))) {
        bParsed = false;
    }
    else {
        /* The minimum command line is complete. */
    }
    return bParsed;
}

static void LogNativeApp(
    IpsecLogLevel_t eLevel,
    const char *pcMessage,
    void *pvUserData)
{
    const char *pcLevel;

    (void)pvUserData;
    switch (eLevel) {
    case IPSEC_LOG_ERROR:
        pcLevel = "error";
        break;
    case IPSEC_LOG_WARNING:
        pcLevel = "warning";
        break;
    case IPSEC_LOG_INFO:
        pcLevel = "info";
        break;
    default:
        pcLevel = "debug";
        break;
    }
    (void)fprintf(stderr, "libipsec_native[%s]: %s\n", pcLevel, pcMessage);
}

static void HandleNativeAppSignal(int iSignal)
{
    (void)iSignal;
    RequestNativeAppStop();
}

static IpsecError_t RunNativeAppCommand(
    IpsecContext_t *pContext,
    const NativeAppArguments_t *pArguments,
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime)
{
    IpsecError_t eError;

    if (0 == strcmp("check", pArguments->pcCommand)) {
        eError = ShowNativeAppStatus(pContext, "daemon");
    }
    else if (0 == strcmp("load", pArguments->pcCommand)) {
        eError = LoadNativeAppResources(pContext, pConfig, pRuntime);
    }
    else if (0 == strcmp("unload", pArguments->pcCommand)) {
        eError = RemoveIpsecConnection(pContext,
                                       pConfig->acConnectionName);
        if ((IPSEC_OK == eError) && pArguments->bClearCredentials) {
            eError = ClearIpsecCredentials(pContext);
        }
        else {
            /* Preserve the unload result or retain shared credentials. */
        }
    }
    else if (0 == strcmp("up", pArguments->pcCommand)) {
        eError = LoadNativeAppResources(pContext, pConfig, pRuntime);
        if (IPSEC_OK == eError) {
            eError = StartNativeAppConnection(pContext, pConfig, pRuntime);
        }
        else {
            /* Preserve the resource load error. */
        }
    }
    else if (0 == strcmp("down", pArguments->pcCommand)) {
        eError = StopNativeAppConnection(pContext, pConfig, true,
                                         pArguments->bClearCredentials);
    }
    else if (0 == strcmp("rekey-ike", pArguments->pcCommand)) {
        eError = RekeyIpsecIke(pContext, pConfig->acConnectionName);
    }
    else if (0 == strcmp("rekey-child", pArguments->pcCommand)) {
        eError = RekeyIpsecChild(pContext, pConfig->acChildName);
    }
    else if (0 == strcmp("status", pArguments->pcCommand)) {
        eError = ShowNativeAppStatus(pContext,
                                     pArguments->pcStatusScope);
    }
    else if (0 == strcmp("loop", pArguments->pcCommand)) {
        eError = RunNativeAppLoop(pContext, pConfig, pRuntime,
                                  &pArguments->Loop);
    }
    else if (0 == strcmp("clear-credentials", pArguments->pcCommand)) {
        eError = ClearIpsecCredentials(pContext);
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    return eError;
}

int main(int iArgumentCount, char **ppcArguments)
{
    NativeAppArguments_t Arguments;
    NativeAppConfig_t AppConfig;
    NativeAppRuntimeConfig_t Runtime;
    IpsecConfig_t Config = {.uiStructSize = sizeof(IpsecConfig_t)};
    IpsecContext_t *pContext = NULL;
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;
    int32_t iResult = 1;

    if (!ParseNativeAppArguments(iArgumentCount, ppcArguments, &Arguments)) {
        PrintNativeAppUsage(ppcArguments[0]);
        return 2;
    }
    else if (Arguments.bHelp) {
        PrintNativeAppUsage(ppcArguments[0]);
        return 0;
    }
    else {
        /* Continue with the requested operation. */
    }
    eError = LoadNativeAppConfig(Arguments.pcConfigPath, &AppConfig,
                                 acError, sizeof(acError));
    if (IPSEC_OK == eError) {
        eError = BuildNativeAppRuntimeConfig(&AppConfig, &Runtime,
                                             acError, sizeof(acError));
    }
    else {
        /* Preserve the configuration parser error. */
    }
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "configuration failed: %s (%s)\n",
                      acError, GetIpsecErrorString(eError));
        return 1;
    }
    else {
        /* Connect to charon using the converted v15 configuration. */
    }
    Config.pcViciSocketPath = AppConfig.acViciSocket;
    Config.uiConnectTimeoutMs = AppConfig.uiTimeoutMs;
    Config.uiCommandTimeoutMs = AppConfig.uiTimeoutMs;
    if (Arguments.bVerbose) {
        Config.pLogCallback = LogNativeApp;
    }
    else {
        /* Keep the library silent by default. */
    }
    eError = InitializeIpsec(&pContext, &Config);
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "InitializeIpsec failed: %s\n",
                      GetIpsecErrorString(eError));
        return 1;
    }
    else {
        (void)signal(SIGINT, HandleNativeAppSignal);
        (void)signal(SIGTERM, HandleNativeAppSignal);
    }
    eError = RunNativeAppCommand(pContext, &Arguments, &AppConfig, &Runtime);
    if (IPSEC_OK == eError) {
        iResult = 0;
    }
    else {
        (void)fprintf(stderr, "%s failed: %s\n", Arguments.pcCommand,
                      GetIpsecErrorString(eError));
    }
    DeinitializeIpsec(pContext);
    return iResult;
}
