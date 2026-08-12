#ifndef IPSEC_APP_INTERNAL_H
#define IPSEC_APP_INTERNAL_H

#include "ipsec.h"

#include <stdbool.h>
#include <stdint.h>

#define NATIVE_APP_PATH_LENGTH             512U
#define NATIVE_APP_PROPOSAL_TEXT_LENGTH   1024U
#define NATIVE_APP_PROPOSAL_COUNT           32U
#define NATIVE_APP_ERROR_TEXT_LENGTH       256U
#define NATIVE_APP_PSK_MAX_LENGTH        65535U

typedef enum NativeAppRole {
    NATIVE_APP_ROLE_INITIATOR = 0,
    NATIVE_APP_ROLE_RESPONDER
} NativeAppRole_t;

typedef struct NativeAppConfig {
    NativeAppRole_t eRole;
    char acLocalAddress[IPSEC_ADDRESS_LENGTH];
    char acRemoteAddress[IPSEC_ADDRESS_LENGTH];
    char acLocalId[IPSEC_ID_LENGTH];
    char acRemoteId[IPSEC_ID_LENGTH];
    char acPskFile[NATIVE_APP_PATH_LENGTH];
    char acViciSocket[NATIVE_APP_PATH_LENGTH];
    char acConnectionName[IPSEC_NAME_LENGTH];
    char acChildName[IPSEC_NAME_LENGTH];
    char acIkeProposals[NATIVE_APP_PROPOSAL_TEXT_LENGTH];
    char acEspProposals[NATIVE_APP_PROPOSAL_TEXT_LENGTH];
    IpsecMode_t eMode;
    bool bChildlessIke;
    bool bTerminateOnExit;
    uint32_t uiTimeoutMs;
} NativeAppConfig_t;

typedef struct NativeAppRuntimeConfig {
    IpsecConnectionConfig_t Connection;
    char acLocalTrafficSelector[IPSEC_SELECTOR_LIST_LENGTH];
    char acRemoteTrafficSelector[IPSEC_SELECTOR_LIST_LENGTH];
    char aacIkeProposals[NATIVE_APP_PROPOSAL_COUNT]
                         [IPSEC_PROPOSAL_LENGTH];
    char aacEspProposals[NATIVE_APP_PROPOSAL_COUNT]
                         [IPSEC_PROPOSAL_LENGTH];
    const char *pacLocalAddresses[1];
    const char *pacRemoteAddresses[1];
    const char *pacLocalTrafficSelectors[1];
    const char *pacRemoteTrafficSelectors[1];
    const char *pacIkeProposals[NATIVE_APP_PROPOSAL_COUNT];
    const char *pacEspProposals[NATIVE_APP_PROPOSAL_COUNT];
} NativeAppRuntimeConfig_t;

typedef struct NativeAppSecret {
    uint8_t *pucData;
    uint32_t uiLength;
} NativeAppSecret_t;

typedef struct NativeAppLoopOptions {
    uint32_t uiCount;
    uint32_t uiDelayMs;
    bool bContinueOnError;
    bool bClearCredentials;
} NativeAppLoopOptions_t;

void InitializeNativeAppConfig(NativeAppConfig_t *pConfig);

IpsecError_t LoadNativeAppConfig(
    const char *pcPath,
    NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t BuildNativeAppRuntimeConfig(
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t ReadNativeAppSecret(
    const NativeAppConfig_t *pConfig,
    NativeAppSecret_t *pSecret);

void DestroyNativeAppSecret(NativeAppSecret_t *pSecret);

IpsecError_t LoadNativeAppResources(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime);

IpsecError_t StartNativeAppConnection(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppRuntimeConfig_t *pRuntime);

IpsecError_t StopNativeAppConnection(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    bool bRemoveConnection,
    bool bClearCredentials);

IpsecError_t RunNativeAppLoop(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime,
    const NativeAppLoopOptions_t *pOptions);

IpsecError_t ShowNativeAppStatus(
    IpsecContext_t *pContext,
    const char *pcScope);

void RequestNativeAppStop(void);

#endif
