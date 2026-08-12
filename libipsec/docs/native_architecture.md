# Native IPsec Library 아키텍처

## 1. 설계 목표

`libipsec`는 IKEv2/IPsec 엔진을 구현하지 않는다. 독립 프로세스로 실행 중인 strongSwan `charon`을 VICI IPC로 제어하고, Linux kernel의 XFRM/network 상태를 Netlink와 `/proc`로 조회하는 C11 라이브러리다.

```text
Application
    |
    v
libipsec
    |
    +-- VICI ---------- charon
    |
    +-- NETLINK_XFRM -- Kernel XFRM
    |
    +-- /proc --------- XFRM statistics
    |
    +-- NETLINK_ROUTE - Kernel Network
```

strongSwan GPL library에는 링크하지 않는다. VICI wire protocol을 독립적으로 구현하며, Linux UAPI header를 통해 Netlink message를 처리한다.

## 2. 범위

### 구현 범위

- VICI Unix Domain Socket 연결, request/response, streamed event
- 연결 설정 load/unload/list
- PSK load와 VICI credential clear
- IKE/CHILD initiate, terminate, rekey
- IKE/CHILD structured status
- daemon version/status와 loaded algorithms
- XFRM state/policy read-only dump
- `/proc/net/xfrm_stat` key/value 조회
- interface/address/route read-only dump
- static/shared library

### 제외 범위

- charon 시작/종료 또는 service manager 제어
- IKE/ESP 암호/상태 머신 구현
- XFRM state/policy 추가, 변경, 삭제
- route/link/address 추가, 변경, 삭제
- firewall, packet capture, UDP 시험 트래픽
- baseline/cross/exhaustive 시험 orchestration과 report

## 3. 디렉터리

```text
libipsec/
|-- LICENSES.md
|-- include/
|   |-- ipsec.h
|   |-- ipsec_types.h
|   `-- ipsec_error.h
|-- ipsec/
|   |-- CMakeLists.txt
|   |-- Makefile
|   |-- Makefile.host
|   |-- Makefile.zynqmp
|   |-- cmake/
|   |   `-- toolchains/
|   |-- internal/
|   |   `-- ipsec_internal.h
|   |-- core/
|   |   |-- ipsec.c
|   |   |-- error.c
|   |   |-- log.c
|   |   |-- memory.c
|   |   `-- secure_zero.c
|   |-- vici/
|   |   |-- vici_transport.c
|   |   |-- vici_packet.c
|   |   |-- vici_parser.c
|   |   |-- vici_client.c
|   |   |-- vici_connection.c
|   |   |-- vici_credential.c
|   |   |-- vici_sa.c
|   |   |-- vici_algorithm.c
|   |   `-- vici_stats.c
|   |-- xfrm/
|   |   |-- xfrm_netlink.c
|   |   |-- xfrm_state.c
|   |   |-- xfrm_policy.c
|   |   `-- xfrm_stats.c
|   `-- route/
|       |-- rtnetlink.c
|       |-- interface.c
|       |-- address.c
|       `-- route.c
|-- apps/
|   |-- Makefile
|   |-- app_internal.h
|   |-- config.c
|   |-- lifecycle.c
|   |-- main.c
|   |-- status.c
|   `-- README.md
`-- tests/
    |-- unit/
    |-- fixtures/
    `-- integration/
```

## 4. Context와 dependency 경계

public header에는 opaque context만 노출한다.

```c
typedef struct IpsecContext IpsecContext_t;
```

내부 context는 다음을 소유한다.

- VICI command socket과 현재 연결 상태
- 선택한 socket path
- connect/send/receive timeout
- command mutex
- logger callback과 user data
- 마지막 transport 오류 진단 정보

Netlink dump socket은 API 호출별로 만들고 닫는다. 이 방식은 context에 Netlink sequence state를 장기간 저장하지 않고 여러 context 사이의 결합을 피한다.

## 5. VICI protocol 기준

호환 기준은 strongSwan 5.8.4의 공식 VICI protocol 문서다.

### transport frame

```text
+----------------------+--------------------------+
| uint32 network length| packet bytes             |
+----------------------+--------------------------+
```

- length는 4-byte header를 제외한 packet 길이다.
- 최대 수신 segment는 512 KiB로 제한한다.
- partial send/receive와 `EINTR`를 처리한다.
- deadline 기반 `poll()`로 connect/send/receive timeout을 구현한다.
- peer close, `EPIPE`, `ECONNRESET`, malformed frame은 연결을 폐기한다.

### packet

- `CMD_REQUEST=0`
- `CMD_RESPONSE=1`
- `CMD_UNKNOWN=2`
- `EVENT_REGISTER=3`
- `EVENT_UNREGISTER=4`
- `EVENT_CONFIRM=5`
- `EVENT_UNKNOWN=6`
- `EVENT=7`

named packet은 packet type 뒤에 1-byte name length와 non-NUL ASCII name을 갖는다.

### message

- `SECTION_START=1`
- `SECTION_END=2`
- `KEY_VALUE=3`
- `LIST_START=4`
- `LIST_ITEM=5`
- `LIST_END=6`

name은 1-byte length, value는 2-byte network-order length를 사용한다. parser는 section/list balance, duplicate/invalid placement, 모든 boundary를 검증한다.

## 6. VICI command 동시성

VICI command response에는 sequence ID가 없다. 따라서 한 socket에서는 한 번에 하나의 command만 진행할 수 있다.

초기 구현 정책:

- 동일 context의 public VICI API는 mutex로 직렬화한다.
- 서로 다른 context는 독립적으로 병렬 실행할 수 있다.
- streamed query는 필요한 event를 등록한 후 command를 보내고, response가 올 때까지 event와 response를 함께 소비한 뒤 event를 해제한다.
- command 중 도착한 예상 event는 command parser에 전달한다.
- 예상하지 않은 event는 무시하되 malformed event는 protocol error로 처리한다.
- transport 실패 시 안전한 read-only request는 한 번 reconnect/retry할 수 있다.
- 상태 변경 request는 결과가 불확실해질 수 있으므로 자동 재전송하지 않는다. caller가 상태를 조회한 뒤 판단한다.

## 7. 비동기와 wait 정책

초기 구현에는 background event thread를 두지 않는다.

- 즉시 반환 initiate/terminate는 VICI `timeout=-1`을 사용한다.
- blocking control API는 caller가 지정한 VICI timeout을 사용한다.
- `Wait*()` API는 bounded interval로 `list-sas`를 조회한다.
- callback logger는 API를 호출한 thread에서만 호출된다.
- persistent `ike-updown`/`child-updown` subscription은 ABI를 깨지 않고 추후 추가할 수 있다.

이 정책은 deinit/event-thread race를 제거하고 strongSwan 5.8.4에서 단순하게 동작한다. VICI의 request-scoped `control-log`, `list-sa`, `list-conn` event는 background thread 없이도 정상 처리한다.

## 8. deinit과 thread safety

- 같은 context의 동시 public API 호출은 허용하되 VICI command는 내부에서 직렬화된다.
- list free 함수와 context를 사용하지 않는 Netlink show API는 독립적으로 실행할 수 있다.
- `DeinitializeIpsec()` 호출 중 다른 thread가 같은 context API를 실행하는 것은 허용하지 않는다. caller가 수명 동기화를 책임진다.
- logger callback에서 같은 context의 API를 재진입하면 deadlock할 수 있으므로 금지한다.
- mutex는 VICI transaction과 context 설정 변경에만 사용하고 logger callback 호출 전에는 가능하면 해제한다.

## 9. timeout

- connect timeout, command timeout, wait timeout을 구분한다.
- `uint32_t` millisecond 단위를 사용한다.
- `0`은 config default를 사용한다. 무한 대기는 public API에서 기본값으로 사용하지 않는다.
- `Wait*()`는 monotonic clock deadline을 사용한다.
- VICI command는 event packet 수와 관계없이 transaction 전체에 하나의
  monotonic absolute deadline을 적용한다.
- system clock 변경이 timeout에 영향을 주지 않게 한다.

## 10. VICI 기능 매핑

| Public 기능 | VICI command/event |
|---|---|
| daemon status | `version`, `stats` |
| algorithms | `get-algorithms` |
| connection add | `load-conn` |
| connection remove | `unload-conn` |
| connection list | `list-conns` + `list-conn` |
| PSK add | `load-shared` |
| credential clear | `clear-creds` |
| IKE/CHILD initiate | `initiate` + optional `control-log` |
| IKE/CHILD terminate | `terminate` + optional `control-log` |
| IKE/CHILD rekey | `rekey` |
| SA list | `list-sas` + `list-sa` |

5.8.4 이후 추가된 key는 optional로 해석한다. 알 수 없는 key/section은 forward compatibility를 위해 건너뛴다.

## 11. 연결 message model

`load-conn` request는 connection name section 아래에 다음 계층을 만든다.

```text
<connection-name> {
    version = 2
    local_addrs = [ ... ]
    remote_addrs = [ ... ]
    proposals = [ ... ]
    local {
        auth = psk
        id = ...
    }
    remote {
        auth = psk
        id = ...
    }
    children {
        <child-name> {
            local_ts = [ ... ]
            remote_ts = [ ... ]
            mode = tunnel|transport
            esp_proposals = [ ... ]
        }
    }
}
```

PFS와 ESN은 별도 암호 구현이 아니라 ESP proposal token과 charon 설정으로 전달된다. NAT detection, NAT-T, rekey, retransmission은 charon이 수행한다.

## 12. XFRM read-only 설계

### 공통 dump

1. `socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM)`
2. request에 `NLM_F_REQUEST | NLM_F_DUMP` 설정
3. unique sequence 지정
4. multipart reply를 `NLMSG_DONE`까지 수신
5. sender PID, sequence, `NLMSG_ERROR`, message 길이 검증

### state

- `XFRM_MSG_GETSA`
- base payload `struct xfrm_usersa_info`
- algorithm, lifetime, replay/ESN 등 `XFRMA_*` attribute decode
- 주소는 family에 따라 `inet_ntop()`으로 변환

### policy

- `XFRM_MSG_GETPOLICY`
- base payload `struct xfrm_userpolicy_info`
- `XFRMA_TMPL` 배열과 mark/interface 관련 optional attribute decode
- IN/OUT/FWD direction을 enum으로 반환

송신 경로에는 `NEWSA`, `UPDSA`, `DELSA`, `NEWPOLICY`, `UPDPOLICY`, `DELPOLICY`를 두지 않는다.

## 13. XFRM statistics

- `/proc/net/xfrm_stat`을 `open()`/`read()`로 직접 읽는다.
- 각 줄을 `<key> <uint64>`로 파싱한다.
- 알려진 key만 public 구조체에 매핑한다.
- 알 수 없는 key는 무시한다.
- 잘못된 숫자, overflow, 중복 key는 parse error로 처리한다.
- kernel 버전에 없는 key는 0이며 optional presence mask로 실제 존재 여부를 구분한다.

## 14. NETLINK_ROUTE

| 기능 | request | 주요 payload/attribute |
|---|---|---|
| interface | `RTM_GETLINK` | `ifinfomsg`, `IFLA_IFNAME`, `IFLA_MTU`, `IFLA_ADDRESS`, `IFLA_CARRIER` |
| address | `RTM_GETADDR` | `ifaddrmsg`, `IFA_ADDRESS`, `IFA_LOCAL`, `IFA_LABEL` |
| route | `RTM_GETROUTE` | `rtmsg`, `RTA_DST`, `RTA_GATEWAY`, `RTA_PREFSRC`, `RTA_OIF`, `RTA_PRIORITY`, `RTA_TABLE` |

IPv4/IPv6를 모두 처리한다. multipath route는 1차 구현에서 `IPSEC_ERR_NOT_SUPPORTED`로 전체 dump를 실패시키지 않고, 표현 가능한 first-hop 또는 별도 flag 정책을 문서화한다.

## 15. 메모리와 ownership

- 입력 config의 pointer/string은 API 호출 중에만 borrow한다.
- context config는 필요한 문자열만 내부 복사한다.
- `Get*()`는 library의 표준 allocator로 contiguous item array를 생성한다.
- list item의 문자열은 fixed-size array로 두어 별도 string allocation을 피한다.
- caller는 해당 `Free*List()`를 정확히 한 번 호출한다.
- free 함수는 empty/zero list에 대해 안전하다.
- callback에 전달한 문자열은 callback 반환 시 무효다.
- PSK raw bytes는 request 완료 직후 secure-zero 대상 buffer에서 제거한다.

## 16. 오류 처리

모든 public 함수는 `IpsecError_t`를 반환한다. errno와 daemon `errmsg`는 logger용 상세 정보로 사용하지만 public 반환 코드는 안정된 library enum으로 정규화한다.

주요 분류:

- argument/range/memory
- VICI connect/timeout/transport/protocol/daemon response
- connection/IKE/CHILD not found 또는 operation failed
- Netlink socket/send/receive/parse
- permission/not-supported/internal

## 17. 로깅

- stdout/stderr에 직접 출력하지 않는다.
- logger 미등록 시 조용히 동작한다.
- format은 stack bounded buffer와 `vsnprintf()`를 사용한다.
- PSK/private key/raw credential, credential VICI message dump는 로그하지 않는다.
- malformed packet 진단에는 offset와 element type만 남기고 payload 전체를 출력하지 않는다.

## 18. 보안 및 robust parsing

- 모든 size add/multiply 전에 overflow를 검사한다.
- network length가 최대 frame보다 크면 연결을 폐기한다.
- name/value length가 남은 buffer보다 크면 즉시 protocol error다.
- section depth와 list item 수에 상한을 둔다.
- Netlink attribute iteration은 `RTA_OK`에만 의존하지 않고 payload 잔여 길이를 별도로 확인한다.
- 모든 fd는 `CLOEXEC`로 만들고 모든 오류 경로에서 닫는다.

## 19. 빌드와 의존성

- 주 빌드 시스템: CMake
- 보조 빌드 시스템: GNU Make
- public link dependency: libc, pthread
- strongSwan library dependency: 없음
- Linux 전용 모듈은 `<linux/xfrm.h>`, `<linux/rtnetlink.h>` 등 UAPI header 사용
- `readelf -d`, `ldd`, `nm -D` 검증 절차를 README에 제공

## 20. Phase 2 결정 사항

- context별 VICI socket 1개와 command mutex
- background event thread 없음
- public async control은 VICI immediate return + 별도 wait API
- logger callback은 caller thread에서 호출
- `DeinitializeIpsec()`와 다른 동일-context 호출의 동시 실행 금지
- Netlink는 API 호출별 socket
- list는 library allocation, 전용 free 함수
- public naming은 합의한 PascalCase/동사-first 규칙 적용
- type은 `_t`, 고정 폭 정수형 사용
