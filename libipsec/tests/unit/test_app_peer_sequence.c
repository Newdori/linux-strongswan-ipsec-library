#include "app_internal.h"

#include <arpa/inet.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct NativeAppPeerSequenceCase {
    uint32_t uiOrdinal;
    uint32_t uiExpectedGroupId;
    uint32_t uiExpectedLogonId;
} NativeAppPeerSequenceCase_t;

typedef struct NativeAppPeerListenerTestState {
    pthread_mutex_t Mutex;
    pthread_cond_t Condition;
    uint32_t uiEventCount;
    IpsecError_t eError;
} NativeAppPeerListenerTestState_t;

static uint16_t GetNativeAppPeerTestPort(void)
{
    struct sockaddr_in Address;
    socklen_t uiAddressLength = (socklen_t)sizeof(Address);
    int32_t iSocket = (int32_t)socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    uint16_t usPort = 0U;

    assert(0 <= iSocket);
    (void)memset(&Address, 0, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(0 == bind(iSocket, (const struct sockaddr *)&Address,
                     sizeof(Address)));
    assert(0 == getsockname(iSocket, (struct sockaddr *)&Address,
                            &uiAddressLength));
    usPort = ntohs(Address.sin_port);
    (void)close(iSocket);
    return usPort;
}

static void HandleNativeAppPeerTestEvent(
    IpsecError_t eError,
    const NativeAppPeer_t *pPeer,
    const char *pcError,
    void *pvUserData)
{
    NativeAppPeerListenerTestState_t *pState =
        (NativeAppPeerListenerTestState_t *)pvUserData;

    (void)pPeer;
    (void)pcError;
    (void)pthread_mutex_lock(&pState->Mutex);
    pState->eError = eError;
    pState->uiEventCount++;
    (void)pthread_cond_signal(&pState->Condition);
    (void)pthread_mutex_unlock(&pState->Mutex);
}

static void WaitNativeAppPeerTestEvent(
    NativeAppPeerListenerTestState_t *pState,
    uint32_t uiExpectedCount)
{
    struct timespec Timeout;
    int32_t iResult = 0;

    assert(0 == clock_gettime(CLOCK_REALTIME, &Timeout));
    Timeout.tv_sec += 5;
    (void)pthread_mutex_lock(&pState->Mutex);
    while ((pState->uiEventCount < uiExpectedCount) && (0 == iResult)) {
        iResult = pthread_cond_timedwait(&pState->Condition, &pState->Mutex,
                                         &Timeout);
    }
    assert(ETIMEDOUT != iResult);
    assert(0 == iResult);
    assert(IPSEC_OK == pState->eError);
    (void)pthread_mutex_unlock(&pState->Mutex);
}

static void TestNativeAppBackgroundPeerListener(void)
{
    NativeAppConfig_t Initiator;
    NativeAppConfig_t Responder;
    NativeAppPeerTable_t InitiatorTable;
    NativeAppPeerTable_t ResponderTable;
    NativeAppPeerListener_t Listener;
    NativeAppPeerListenerTestState_t State;
    NativeAppPeer_t *pPeer = NULL;
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    uint16_t usPort = GetNativeAppPeerTestPort();
    uint32_t uiIndex;

    (void)memset(&Initiator, 0, sizeof(Initiator));
    (void)memset(&Responder, 0, sizeof(Responder));
    (void)memset(&Listener, 0, sizeof(Listener));
    (void)memset(&State, 0, sizeof(State));
    assert(0 == pthread_mutex_init(&State.Mutex, NULL));
    assert(0 == pthread_cond_init(&State.Condition, NULL));
    assert(IPSEC_OK == InitializeNativeAppPeerTable(&InitiatorTable));
    assert(IPSEC_OK == InitializeNativeAppPeerTable(&ResponderTable));

    Initiator.eRole = NATIVE_APP_ROLE_INITIATOR;
    Initiator.eMode = IPSEC_MODE_TRANSPORT;
    Initiator.uiTimeoutMs = 2000U;
    Initiator.uiPeerPort = usPort;
    (void)snprintf(Initiator.acLocalAddress,
                   sizeof(Initiator.acLocalAddress), "127.0.0.1");
    (void)snprintf(Initiator.acPeerServerAddress,
                   sizeof(Initiator.acPeerServerAddress), "127.0.0.1");
    (void)snprintf(Initiator.acLocalId, sizeof(Initiator.acLocalId),
                   "rcst-controller");
    (void)snprintf(Initiator.acIkeProposals,
                   sizeof(Initiator.acIkeProposals),
                   "aes256-sha256-prfsha256-modp2048");
    (void)snprintf(Initiator.acEspProposals,
                   sizeof(Initiator.acEspProposals), "aes256-sha256");
    Responder = Initiator;
    Responder.eRole = NATIVE_APP_ROLE_RESPONDER;

    assert(IPSEC_OK == StartNativeAppPeerListener(
        &Listener, &Initiator, &InitiatorTable,
        HandleNativeAppPeerTestEvent, &State, acError, sizeof(acError)));
    for (uiIndex = 0U; uiIndex < 2U; uiIndex++) {
        assert(IPSEC_OK == RegisterNativeAppPeer(
            &Responder, &ResponderTable, &pPeer, acError,
            sizeof(acError)));
        assert(NULL != pPeer);
        assert(1U == pPeer->uiGroupId);
        assert((uiIndex + 1U) == pPeer->uiLogonId);
        WaitNativeAppPeerTestEvent(&State, uiIndex + 1U);
    }
    StopNativeAppPeerListener(&Listener);
    assert(2U == InitiatorTable.uiCount);
    assert(1U == InitiatorTable.aPeers[0].uiGroupId);
    assert(1U == InitiatorTable.aPeers[0].uiLogonId);
    assert(1U == InitiatorTable.aPeers[1].uiGroupId);
    assert(2U == InitiatorTable.aPeers[1].uiLogonId);

    DeinitializeNativeAppPeerTable(&ResponderTable);
    DeinitializeNativeAppPeerTable(&InitiatorTable);
    (void)pthread_cond_destroy(&State.Condition);
    (void)pthread_mutex_destroy(&State.Mutex);
}

int main(void)
{
    static const NativeAppPeerSequenceCase_t aCases[] = {
        {0U, 1U, 1U},
        {1U, 1U, 2U},
        {99U, 1U, 100U},
        {100U, 2U, 1U},
        {101U, 2U, 2U},
        {199U, 2U, 100U},
        {200U, 3U, 1U}
    };
    uint32_t uiIndex;

    for (uiIndex = 0U;
         uiIndex < (uint32_t)(sizeof(aCases) / sizeof(aCases[0]));
         uiIndex++) {
        uint32_t uiGroupId = 0U;
        uint32_t uiLogonId = 0U;
        IpsecError_t eError = GetNativeAppPeerSequence(
            aCases[uiIndex].uiOrdinal, &uiGroupId, &uiLogonId);

        assert(IPSEC_OK == eError);
        assert(aCases[uiIndex].uiExpectedGroupId == uiGroupId);
        assert(aCases[uiIndex].uiExpectedLogonId == uiLogonId);
    }
    assert(IPSEC_ERR_INVALID_ARGUMENT ==
           GetNativeAppPeerSequence(0U, NULL, NULL));
    TestNativeAppBackgroundPeerListener();
    return 0;
}
