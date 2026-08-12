#ifndef IPSEC_INTERNAL_H
#define IPSEC_INTERNAL_H

#define _POSIX_C_SOURCE 200809L

#include "ipsec.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define IPSEC_DEFAULT_CONNECT_TIMEOUT_MS 3000U
#define IPSEC_DEFAULT_COMMAND_TIMEOUT_MS 10000U
#define IPSEC_VICI_SOCKET_PATH_LENGTH 108U
#define IPSEC_LOG_MESSAGE_LENGTH 1024U

struct IpsecContext {
    int32_t iViciSocket;
    char acViciSocketPath[IPSEC_VICI_SOCKET_PATH_LENGTH];
    uint32_t uiConnectTimeoutMs;
    uint32_t uiCommandTimeoutMs;
    uint64_t ullCommandDeadlineMs;
    pthread_mutex_t CommandMutex;
    bool bCommandMutexInitialized;
    IpsecLogCallback_t pLogCallback;
    void *pvLogUserData;
};

void LogIpsec(
    const IpsecContext_t *pContext,
    IpsecLogLevel_t eLevel,
    const char *pcFormat,
    ...);

void SecureZeroIpsec(
    void *pvMemory,
    size_t zLength);

IpsecError_t CopyIpsecString(
    char *pcDestination,
    size_t zDestinationLength,
    const uint8_t *pucSource,
    size_t zSourceLength);

IpsecError_t ParseIpsecUint32(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint32_t *puiValue,
    uint32_t uiBase);

IpsecError_t ParseIpsecUint64(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint64_t *pullValue,
    uint32_t uiBase);

IpsecError_t AppendIpsecText(
    char *pcDestination,
    size_t zDestinationLength,
    const uint8_t *pucValue,
    size_t zValueLength,
    const char *pcSeparator);

uint64_t GetIpsecMonotonicMilliseconds(void);

IpsecError_t SleepIpsecMilliseconds(uint32_t uiMilliseconds);

bool CalculateIpsecArraySize(
    uint32_t uiCount,
    size_t zItemSize,
    size_t *pzAllocationSize);

#endif
