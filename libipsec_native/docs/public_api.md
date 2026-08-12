# Public API 설계

## 1. ABI 원칙

- public header는 `ipsec.h`, `ipsec_types.h`, `ipsec_error.h` 세 개다.
- 내부 VICI/Netlink 구조는 노출하지 않는다.
- 모든 함수명은 동사로 시작하는 PascalCase다.
- `typedef struct` 타입 이름은 `_t`로 끝낸다.
- integer는 `<stdint.h>`의 고정 폭 타입을 사용한다.
- 함수 결과는 `IpsecError_t`로 반환한다.
- public struct에는 `uiStructSize`를 두어 향후 필드 확장을 검증한다.

## 2. Context lifecycle

```c
typedef struct IpsecContext IpsecContext_t;

IpsecError_t InitializeIpsec(
    IpsecContext_t **ppContext,
    const IpsecConfig_t *pConfig);

void DeinitializeIpsec(
    IpsecContext_t *pContext);
```

`InitializeIpsec()`는 지정 socket에 연결하고 VICI `version` 요청으로 daemon 준비를 확인한다. 사용자가 socket을 지정하지 않으면 `/run/charon.vici`, `/var/run/charon.vici` 순서로 시도한다.

## 3. Context config

```c
typedef void (*IpsecLogCallback_t)(
    IpsecLogLevel_t eLevel,
    const char *pcMessage,
    void *pvUserData);

typedef struct IpsecConfig {
    uint32_t uiStructSize;
    const char *pcViciSocketPath;
    uint32_t uiConnectTimeoutMs;
    uint32_t uiCommandTimeoutMs;
    IpsecLogCallback_t pLogCallback;
    void *pvLogUserData;
} IpsecConfig_t;
```

- config pointer와 문자열은 호출 중 borrow한다.
- context는 socket path를 내부 복사한다.

## 4. Connection config

```c
typedef enum IpsecMode {
    IPSEC_MODE_TUNNEL = 0,
    IPSEC_MODE_TRANSPORT
} IpsecMode_t;

typedef enum IpsecAuthMethod {
    IPSEC_AUTH_PSK = 0,
    IPSEC_AUTH_CERTIFICATE,
    IPSEC_AUTH_EAP
} IpsecAuthMethod_t;

typedef enum IpsecEsnMode {
    IPSEC_ESN_AUTO = 0,
    IPSEC_ESN_DISABLED,
    IPSEC_ESN_ENABLED
} IpsecEsnMode_t;

typedef struct IpsecStringListView {
    const char *const *ppcItems;
    uint32_t uiCount;
} IpsecStringListView_t;

typedef struct IpsecConnectionConfig {
    uint32_t uiStructSize;
    const char *pcName;
    const char *pcChildName;
    IpsecStringListView_t LocalAddresses;
    IpsecStringListView_t RemoteAddresses;
    IpsecAuthMethod_t eLocalAuth;
    IpsecAuthMethod_t eRemoteAuth;
    const char *pcLocalId;
    const char *pcRemoteId;
    IpsecStringListView_t IkeProposals;
    IpsecStringListView_t EspProposals;
    IpsecStringListView_t LocalTrafficSelectors;
    IpsecStringListView_t RemoteTrafficSelectors;
    IpsecMode_t eMode;
    IpsecEsnMode_t eEsn;
    bool bEnablePfs;
    bool bEnableMobike;
    bool bEnableFragmentation;
    bool bForceUdpEncapsulation;
    bool bForceChildlessIke;
    uint32_t uiDpdDelayMs;
    uint32_t uiDpdTimeoutMs;
    uint64_t ullIkeRekeyTimeMs;
    uint64_t ullIkeLifetimeMs;
    uint64_t ullChildRekeyTimeMs;
    uint64_t ullChildLifetimeMs;
} IpsecConnectionConfig_t;
```

`ullIkeLifetimeMs`는 strongSwan IKE_SA의 최대 운용 주기를 의미하며 VICI
설정의 `reauth_time`으로 매핑한다. CHILD의 `ullChildLifetimeMs`는
`life_time`으로 매핑한다. 값이 0이면 해당 strongSwan 기본값을 유지한다.

설계상 PFS/ESN 필드와 proposal 문자열이 충돌하지 않도록 validation한다. PFS group은 ESP proposal에 포함하며 `bEnablePfs`는 PFS 없는 proposal의 실수 사용을 탐지하는 validation intent다. ESN은 proposal의 `esn/noesn` token을 명시적으로 보강하거나 충돌을 거부한다.

## 5. Connection API

```c
IpsecError_t AddIpsecConnection(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig);

IpsecError_t RemoveIpsecConnection(
    IpsecContext_t *pContext,
    const char *pcName);

IpsecError_t GetIpsecConnections(
    IpsecContext_t *pContext,
    IpsecConnectionList_t *pList);

void FreeIpsecConnectionList(
    IpsecConnectionList_t *pList);
```

`RemoveIpsecConnection()`은 active SA를 자동 terminate하지 않고 VICI connection definition만 unload한다.

## 6. Credential API

```c
typedef struct IpsecPsk {
    uint32_t uiStructSize;
    const char *pcId;
    const uint8_t *pucData;
    uint32_t uiDataLength;
    IpsecStringListView_t Owners;
} IpsecPsk_t;

IpsecError_t AddIpsecPsk(
    IpsecContext_t *pContext,
    const IpsecPsk_t *pPsk);

IpsecError_t ClearIpsecCredentials(
    IpsecContext_t *pContext);
```

PSK pointer는 호출 중에만 읽는다. library는 PSK를 context에 보관하지 않는다. VICI request용 임시 buffer는 전송 직후 안전하게 지운다.

향후 certificate/private key API는 별도 typed credential 구조체와 함수로 추가한다.

## 7. Control mode

```c
typedef enum IpsecControlMode {
    IPSEC_CONTROL_WAIT = 0,
    IPSEC_CONTROL_IMMEDIATE
} IpsecControlMode_t;

typedef struct IpsecControlOptions {
    uint32_t uiStructSize;
    IpsecControlMode_t eMode;
    uint32_t uiTimeoutMs;
} IpsecControlOptions_t;
```

`WAIT`는 VICI command가 완료될 때까지 기다린다. `IMMEDIATE`는 VICI timeout `-1` 의미를 사용한다.

## 8. IKE API

```c
IpsecError_t InitiateIpsecIke(
    IpsecContext_t *pContext,
    const char *pcConnectionName,
    const IpsecControlOptions_t *pOptions);

IpsecError_t TerminateIpsecIke(
    IpsecContext_t *pContext,
    const char *pcIkeName,
    const IpsecControlOptions_t *pOptions);

IpsecError_t RekeyIpsecIke(
    IpsecContext_t *pContext,
    const char *pcIkeName);

IpsecError_t WaitIpsecIkeEstablished(
    IpsecContext_t *pContext,
    const char *pcIkeName,
    uint32_t uiTimeoutMs);
```

## 9. CHILD API

```c
IpsecError_t InitiateIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName,
    const IpsecControlOptions_t *pOptions);

IpsecError_t TerminateIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName,
    const IpsecControlOptions_t *pOptions);

IpsecError_t RekeyIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName);

IpsecError_t WaitIpsecChildInstalled(
    IpsecContext_t *pContext,
    const char *pcChildName,
    uint32_t uiTimeoutMs);
```

PFS CHILD는 IKE-only 연결을 시작한 뒤 `InitiateIpsecChild()`를 호출하는 흐름을 지원한다.

## 10. Structured show API

```c
IpsecError_t GetIpsecIkeSas(
    IpsecContext_t *pContext,
    IpsecIkeSaList_t *pList);

IpsecError_t GetIpsecChildSas(
    IpsecContext_t *pContext,
    IpsecChildSaList_t *pList);

IpsecError_t GetIpsecAlgorithms(
    IpsecContext_t *pContext,
    IpsecAlgorithmList_t *pList);

IpsecError_t GetIpsecDaemonStatus(
    IpsecContext_t *pContext,
    IpsecDaemonStatus_t *pStatus);
```

각 list는 library가 할당하며 대응하는 free 함수를 제공한다.

```c
void FreeIpsecIkeSaList(IpsecIkeSaList_t *pList);
void FreeIpsecChildSaList(IpsecChildSaList_t *pList);
void FreeIpsecAlgorithmList(IpsecAlgorithmList_t *pList);
```

## 11. IKE/CHILD 주요 정보

```c
typedef struct IpsecIkeSaInfo {
    char acName[64];
    char acState[32];
    bool bEstablished;
    bool bInitiator;
    bool bNatLocal;
    bool bNatRemote;
    char acLocalAddress[64];
    char acRemoteAddress[64];
    char acLocalId[128];
    char acRemoteId[128];
    char acProposal[256];
    uint64_t ullUniqueId;
    uint64_t ullEstablishedTimeMs;
    uint64_t ullRekeyTimeMs;
} IpsecIkeSaInfo_t;

typedef struct IpsecChildSaInfo {
    char acIkeName[64];
    char acName[64];
    char acState[32];
    char acProposal[256];
    char acLocalTrafficSelectors[512];
    char acRemoteTrafficSelectors[512];
    IpsecMode_t eMode;
    bool bEsn;
    bool bUdpEncapsulation;
    uint32_t uiReqid;
    uint32_t uiInboundSpi;
    uint32_t uiOutboundSpi;
    uint64_t ullBytesIn;
    uint64_t ullBytesOut;
    uint64_t ullPacketsIn;
    uint64_t ullPacketsOut;
    uint64_t ullInstallTimeMs;
    uint64_t ullRekeyTimeMs;
    uint64_t ullLifetimeMs;
} IpsecChildSaInfo_t;
```

## 12. XFRM API

```c
IpsecError_t GetIpsecXfrmStates(
    IpsecContext_t *pContext,
    IpsecXfrmStateList_t *pList);

IpsecError_t GetIpsecXfrmPolicies(
    IpsecContext_t *pContext,
    IpsecXfrmPolicyList_t *pList);

IpsecError_t GetIpsecXfrmStatistics(
    IpsecXfrmStatistics_t *pStatistics);

void FreeIpsecXfrmStateList(IpsecXfrmStateList_t *pList);
void FreeIpsecXfrmPolicyList(IpsecXfrmPolicyList_t *pList);
```

XFRM show는 context logger를 사용할 수 있지만 list는 library의 표준 allocator로 할당한다. statistics와 route show는 context 없이 동작하고 logger 미등록 상태와 같이 조용히 오류를 반환한다.

## 13. Route API

```c
IpsecError_t GetIpsecInterfaces(IpsecInterfaceList_t *pList);
IpsecError_t GetIpsecAddresses(IpsecAddressList_t *pList);
IpsecError_t GetIpsecRoutes(IpsecRouteList_t *pList);

void FreeIpsecInterfaceList(IpsecInterfaceList_t *pList);
void FreeIpsecAddressList(IpsecAddressList_t *pList);
void FreeIpsecRouteList(IpsecRouteList_t *pList);
```

## 14. Error API

```c
typedef enum IpsecError {
    IPSEC_OK = 0,
    IPSEC_ERR_INVALID_ARGUMENT,
    IPSEC_ERR_NO_MEMORY,
    IPSEC_ERR_VICI_CONNECT,
    IPSEC_ERR_VICI_TRANSPORT,
    IPSEC_ERR_VICI_PROTOCOL,
    IPSEC_ERR_VICI_TIMEOUT,
    IPSEC_ERR_VICI_COMMAND,
    IPSEC_ERR_DAEMON_NOT_RUNNING,
    IPSEC_ERR_CONNECTION_NOT_FOUND,
    IPSEC_ERR_IKE_FAILED,
    IPSEC_ERR_CHILD_FAILED,
    IPSEC_ERR_NETLINK_SOCKET,
    IPSEC_ERR_NETLINK_SEND,
    IPSEC_ERR_NETLINK_RECV,
    IPSEC_ERR_NETLINK_PARSE,
    IPSEC_ERR_FILE_OPEN,
    IPSEC_ERR_FILE_READ,
    IPSEC_ERR_PERMISSION,
    IPSEC_ERR_BUFFER_TOO_SMALL,
    IPSEC_ERR_NOT_SUPPORTED,
    IPSEC_ERR_INTERNAL
} IpsecError_t;

const char *GetIpsecErrorString(IpsecError_t eError);
```

## 15. Ownership 표

| 값 | 소유자 | 유효기간/해제 |
|---|---|---|
| config 입력 문자열 | caller | API 호출 동안 |
| PSK bytes | caller | `AddIpsecPsk()` 호출 동안 |
| context | library allocation, caller handle | `DeinitializeIpsec()` |
| `Get*()` list items | library | 대응 `Free*List()` |
| fixed array 문자열 | list item 내부 | list free 전까지 |
| logger message | library temporary | callback 반환 전까지 |
| error string | static library storage | process lifetime, free 금지 |

## 16. 사용 흐름

```c
IpsecContext_t *pContext = NULL;
IpsecConfig_t Config = {
    .uiStructSize = sizeof(IpsecConfig_t),
    .pcViciSocketPath = "/var/run/charon.vici",
    .uiConnectTimeoutMs = 3000U,
    .uiCommandTimeoutMs = 10000U
};

IpsecError_t eError = InitializeIpsec(&pContext, &Config);
if (IPSEC_OK == eError) {
    eError = AddIpsecConnection(pContext, &Connection);
}
else {
    /* 초기화 오류 */
}

if (IPSEC_OK == eError) {
    eError = AddIpsecPsk(pContext, &Psk);
}
else {
    /* 이전 단계 오류 유지 */
}

if (IPSEC_OK == eError) {
    eError = InitiateIpsecChild(pContext, "vpn1-child", &ControlOptions);
}
else {
    /* 이전 단계 오류 유지 */
}

DeinitializeIpsec(pContext);
```

## 17. Phase 2 완료 기준

- module boundary 확정
- thread/event/deinit policy 확정
- timeout와 ownership 확정
- public 함수와 핵심 public type 확정
- VICI 5.8.4 command mapping 확정
- read-only Netlink 경계 확정

Phase 3에서 이 문서의 API를 실제 header로 옮기고 compiler로 ABI 선언을 검증한다.
