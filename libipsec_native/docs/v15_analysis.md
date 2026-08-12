# ipsec_app_project_v15 분석

## 1. 분석 범위와 결론

- 원본: 별도로 제공된 `ipsec_app_project_v15` 소스 트리
- 분석일: 2026-08-12
- 원본은 수정하지 않았다.
- v15는 재사용 라이브러리가 아니라 두 시험 단말을 동기화하여 strongSwan 상호운용성과 데이터 경로를 검증하는 단일 실행 프로그램이다.
- 제품 동작과 직접 관련된 의미는 `src/strongswan.c`, `src/xfrm.c`, `src/config.c`, `src/main.c` 일부에 있다.
- 실제 제어 구현은 `swanctl`, `systemctl`, `ip`, `cat` 실행과 CLI 출력 파싱에 결합되어 있으므로 신규 라이브러리에 코드를 그대로 옮길 수 없다.
- 제안 문자열, 연결 속성, PSK 검증, SA 대기/정리의 동작 의미는 재사용할 수 있으나 VICI/Netlink 기반으로 다시 구현해야 한다.
- `capture`, UDP 시험 트래픽, peer barrier, matrix/catalog, CSV/report, firewall은 제품 라이브러리에서 제외한다.

## 2. 현재 아키텍처

```text
main.c
  |
  +-- config.c -------- 시험 설정 파일 파싱/검증
  +-- network.c ------- ip link/addr/route 실행
  +-- strongswan.c ---- systemctl 및 swanctl 실행, 텍스트 파싱
  +-- xfrm.c ---------- ip xfrm/cat 실행, 텍스트 파싱
  +-- udp_test.c ------ 시험 UDP와 peer barrier
  +-- capture.c ------- tcpdump 실행/분석
  +-- firewall.c ------ iptables 실행
  +-- report.c -------- 시험 결과 파일/CSV
  +-- process.c ------- fork/exec 기반 공통 실행기
```

정상 시험 케이스의 실제 순서는 다음과 같다.

1. 인터페이스와 경로를 확인하고 필요 시 주소를 설정한다.
2. strongSwan 서비스를 확인하고 필요 시 시작한다.
3. 기존 대상 SA를 종료하고 reqid 기반 XFRM 제거를 확인한다.
4. 임시 `swanctl.conf` 조각과 credential 파일을 생성한다.
5. `swanctl --load-conns`, `--load-creds`를 호출한다.
6. initiator가 IKE/CHILD를 시작하고 양쪽이 SA 설치를 polling한다.
7. 시험용 capture/barrier/UDP/XFRM counter 검증을 수행한다.
8. 대상 IKE SA를 종료하고 SA/XFRM 제거를 polling한다.

근거는 `src/main.c:232`의 `run_test_case()`와 `README.md:243`의 검증 순서다.

## 3. 빌드와 실행 특성

- 빌드 결과는 하나의 실행 파일 `ipsec_app`이다 (`Makefile:1`).
- C11과 `-Wall -Wextra -Wpedantic -Werror`를 이미 사용한다.
- 모든 `src/*.c`가 한 실행 파일에 링크되며 계층 또는 public/private ABI 분리가 없다.
- 실행 시 root를 강제한다 (`src/main.c:1398`).
- logger와 capture session 등 전역 mutable state를 사용하므로 context 기반 라이브러리 구조가 아니다.
- 원본 검증 문서는 Linux 빌드를 PASS로 기록하지만 v15 실제 PC-A/PC-B 회귀 시험은 아직 수행하지 않았다고 명시한다 (`docs/validation/BUILD_VERIFICATION_V15.txt`).

## 4. 외부 명령과 파일 의존성

| 의존성 | 위치 | 현재 목적 | Native 대체 또는 처리 |
|---|---|---|---|
| `swanctl --stats` | `src/strongswan.c:248` | daemon/VICI 준비 확인 | VICI `stats` 요청 |
| `swanctl --version --daemon` | `src/strongswan.c:60` | daemon 버전 | VICI `version` 요청 |
| `swanctl --list-algs` | `src/strongswan.c:70` | 알고리즘 조회 | VICI `list-algs`와 event decode |
| `swanctl --load-conns` | `src/strongswan.c:431` | 연결 설정 적재 | VICI `load-conn` |
| `swanctl --list-conns` | `src/strongswan.c:174` | 설정 확인 | VICI `list-conns`와 `list-conn` event |
| `swanctl --load-creds` | `src/strongswan.c:467` | PSK 적재 | VICI `load-shared` |
| `swanctl --initiate --ike` | `src/strongswan.c:524` | childless IKE 시작 | VICI `initiate`의 `ike` selector |
| `swanctl --initiate --child` | `src/strongswan.c:495` | CHILD 시작 | VICI `initiate`의 `child` selector |
| `swanctl --list-sas` | `src/strongswan.c:643` | IKE/CHILD 조회와 wait | VICI `list-sas`와 `list-sa` event |
| `swanctl --terminate --ike` | `src/strongswan.c:806` | 대상 SA 종료 | VICI `terminate` |
| `systemctl is-active/start` | `src/strongswan.c:215` | daemon 관리 | 제거. `IpsecInit()`에서 VICI connect로 상태만 판정 |
| `ip link`/`ip addr` | `src/network.c:16` | link 및 address 확인/설정 | 조회는 `NETLINK_ROUTE`; 설정은 범위에서 제외 |
| `ip route get` | `src/network.c:40` | 경로 확인 | `NETLINK_ROUTE` route dump/lookup 기반 조회 |
| `ip -d -s xfrm state` | `src/xfrm.c:121` | state/counter 조회 | `NETLINK_XFRM`, `XFRM_MSG_GETSA` dump |
| `ip -d -s xfrm policy` | `src/xfrm.c:136` | policy 조회 | `NETLINK_XFRM`, `XFRM_MSG_GETPOLICY` dump |
| `cat /proc/net/xfrm_stat` | `src/xfrm.c:141` | XFRM 오류 통계 | `open()`/`read()`와 key/value parser |
| `journalctl` | `src/strongswan.c:439` | AppArmor 진단 | 제거. library error와 callback logger 사용 |
| `iptables` | `src/firewall.c` | 시험 UDP 허용 | 제품 라이브러리에서 제외 |
| `tcpdump` | `src/capture.c` | ESP/평문/capture 검증 | 제품 라이브러리에서 제외 |

`src/process.c`는 `fork()`/`execvp()`를 제공하는 공통 명령 실행 계층이다. 신규 라이브러리에 포함하지 않는다. 경로 조합이나 파일 쓰기처럼 일반적인 helper도 command execution 모듈과 분리해 새로 작성한다.

## 5. strongSwan 설정 의미

v15가 생성하는 연결은 `src/strongswan.c:319`에 정의되어 있다.

| 항목 | v15 값/동작 | 신규 API 처리 |
|---|---|---|
| IKE version | 항상 2 | 초기 구현은 IKEv2만 허용 |
| local/remote address | 단일 IPv4 | IPv4/IPv6 문자열을 검증하고 VICI list value로 encode |
| IKE proposal | 사용자 문자열 | 길이/문자 검증 후 VICI `proposals` list로 전달 |
| auth | 양쪽 `psk` | public enum으로 표현, 1차 구현은 PSK |
| local/remote ID | 각 1개 | VICI local/remote auth section으로 전달 |
| MOBIKE | `no` | 설정 필드 또는 보수적 default로 보존 |
| fragmentation | `yes` | 설정 필드 또는 default로 보존 |
| childless | PFS 별도 시험이면 `force`, 아니면 `allow` | IKE-only/CHILD 분리 API 의미로 보존 |
| traffic selector | endpoint `/32` | public API에서 일반 CIDR list로 확장 |
| mode | `transport` 또는 `tunnel` | enum으로 표현 |
| ESP proposal | 사용자 문자열 | PFS/ESN token을 포함해 그대로 전달 |
| start/close action | `none` | library 제어형 default로 보존 |
| DPD action | `clear` | action/time 설정 필드로 확장 |
| NAT-T | 명시 설정 없음 | charon 기본 NAT detection/NAT-T 동작 사용, 필요 시 encapsulation 정책만 노출 |

v15에는 IKE/CHILD rekey API가 없고 lifetime/rekey time도 설정하지 않는다. 신규 라이브러리에서 추가 구현하되 v15에서 재사용했다고 표현해서는 안 된다.

## 6. PSK 처리 분석

현재 구현은 다음 보안 의도를 갖는다.

- PSK 파일 권한의 group/other bit가 없음을 검사한다 (`src/strongswan.c:117`).
- 최소 32문자와 생성 설정 파일에 안전한 ASCII 범위를 검사한다 (`src/strongswan.c:129`).
- connection 설정과 credential 파일을 분리한다.
- credential 파일을 mode 0600으로 만들고 적재 후 삭제한다.
- stack PSK buffer를 cleanup에서 `memset()`한다.

신규 구현에서 유지할 것은 길이/입력 검증과 비밀 로그 금지다. 파일 생성은 제거하고 raw bytes를 VICI `load-shared`의 `data`로 전송한다. 단순 `memset()`은 최적화로 제거될 수 있으므로 `explicit_bzero()` 사용 가능 여부를 감싸는 secure-zero helper를 제공한다. public API는 PSK의 소유권과 호출 후 유효기간을 명시하고, 내부 복사는 최소화한다.

## 7. SA 상태와 lifecycle 의미

v15의 상태 판정은 `swanctl --list-sas`의 포맷된 문자열을 읽어 다음만 추출한다.

- 대상 IKE 이름의 존재 여부
- `ESTABLISHED`
- 대상 CHILD 이름의 존재 여부
- `INSTALLED`
- reqid
- `ESP:` 뒤의 알고리즘 문자열

이 parser는 버전별 출력 형식 차이를 완화하려 하지만 CLI layout에 종속된다 (`src/strongswan.c:592`). 신규 구현에서는 `list-sa` event의 section/key/value를 구조적으로 decode한다.

재사용할 lifecycle 의미:

- IKE-only 시작 후 IKE가 established이고 CHILD가 없는지 확인한다.
- PFS CHILD는 별도 `CREATE_CHILD_SA`로 시작하고 CHILD proposal의 KE를 확인한다.
- 성공 대기는 bounded timeout을 사용한다.
- 종료 요청의 반환값만 신뢰하지 않고 실제 SA 부재를 다시 확인한다.
- CHILD reqid를 확보했다면 종료 후 해당 XFRM state/policy 부재도 확인할 수 있다.

신규 API에서는 blocking/async 의미를 분리한다. 하나의 VICI 연결은 response sequence ID가 없으므로 동일 context의 command는 직렬화해야 한다. list/event stream과 command response가 섞일 수 있음을 parser/client 계층에서 처리한다.

## 8. XFRM 분석

현재 `src/xfrm.c`는 show 결과 문자열에서 `(packets)`, `(bytes)`, `reqid`를 검색한다. state/policy 전체 구조를 제공하지 않으며 `/proc/net/xfrm_stat`의 모든 값을 하나의 합계로 축약한다.

신규 구현 원칙:

- `NETLINK_XFRM`은 dump 조회 전용으로 사용한다.
- SA/policy add/update/delete 메시지는 라이브러리에서 송신하지 않는다.
- `nlmsghdr`, payload, 각 `rtattr` 길이를 단계별로 검증한다.
- 알 수 없는 attribute는 무시하되 malformed/truncated attribute는 오류로 처리한다.
- 여러 dump message를 sequence와 sender PID 기준으로 검증하고 `NLMSG_DONE`까지 수신한다.
- `/proc/net/xfrm_stat`은 알려진 key를 구조체 필드에 매핑하고 알 수 없는 key는 parser 실패 원인으로 삼지 않는다.

## 9. A/B/C 분류

### A. 제품용 의미를 재사용할 항목

| 항목 | 원본 | 재사용 범위 |
|---|---|---|
| 연결 설정 필드 | `app_config_t`, `strongswan_load_configuration()` | 주소, ID, proposal, TS, mode, childless, auth의 의미 |
| 설정 validation 의도 | `src/config.c:147` | 길이, 주소, enum/range, proposal 입력 검증 원칙 |
| PSK validation 의도 | `src/strongswan.c:110` | 민감정보 취급과 검증 원칙 |
| PFS/ESN proposal 사례 | `src/test_catalog.c`, matrix config | 5.8.4 호환 token 회귀 fixture 작성에만 활용 |
| SA wait/cleanup 의미 | `src/strongswan.c:677`, `:725`, `:751` | timeout, 상태 재확인, target-only cleanup |
| reqid correlation | `src/main.c:204`, `src/xfrm.c:65` | VICI CHILD와 kernel XFRM을 reqid로 연관시키는 설계 |
| C11 strict build | `Makefile` | compiler warning 정책 |

소스 코드를 그대로 복사한다는 뜻이 아니라 검증된 동작 의미와 시험 fixture를 재사용한다는 뜻이다.

### B. Native API로 다시 구현할 항목

| 기존 기능 | 신규 구현 |
|---|---|
| swanctl command 조립/실행 | 직접 VICI packet encode/send/receive |
| swanctl config 임시 파일 | VICI message tree 생성 |
| swanctl stdout parser | VICI message/event parser |
| SA polling | VICI structured query, 이후 event 기반 wait 확장 |
| `ip xfrm` parser | `NETLINK_XFRM` UAPI decode |
| `cat /proc/net/xfrm_stat` | 직접 파일 read와 key/value parser |
| `ip link/addr/route` parser | `NETLINK_ROUTE` UAPI decode |
| stdout/stderr logger | context callback logger |
| 전역 상태 | opaque `IpsecContext_t` 내부 상태 |
| `0/-1` 오류 | `IpsecError_t` enum |
| ad-hoc malloc/free | 명시적 list ownership과 `*ListFree()` API |

### C. 시험 전용으로 제거할 항목

- `src/main.c`의 baseline/cross/exhaustive/custom orchestration
- `src/test_matrix.c`, `src/test_catalog.c`의 제품 runtime 포함
- `src/udp_test.c` 전체
- `src/capture.c` 전체
- `src/firewall.c` 전체
- `src/report.c` 전체
- peer barrier, result directory, CSV, strict/capture verdict
- tcpdump/pcap/평문 탐지
- 시험 PSK 생성 CLI와 wrapper script
- systemd/charon process lifecycle 관리

알고리즘 catalog는 runtime 제품 기능이 아니라 unit/integration test fixture 또는 별도 참고 자료로만 둘 수 있다.

## 10. Native replacement mapping

```text
v15 strongswan_ensure_ready()
  -> IpsecInit()
  -> Unix socket connect
  -> VICI version/stats

v15 strongswan_load_configuration()
  -> IpsecConnectionAdd()
  -> VICI load-conn
  -> IpsecCredentialAddPsk()
  -> VICI load-shared

v15 initiate/wait functions
  -> IpsecIkeInitiate()/IpsecChildInitiate()
  -> VICI initiate
  -> IpsecIkeWaitEstablished()/IpsecChildWaitInstalled()
  -> VICI list-sas/list-sa event decode

v15 cleanup_target_sa()
  -> IpsecIkeTerminate()/IpsecChildTerminate()
  -> VICI terminate
  -> structured SA absence confirmation

v15 xfrm_take_snapshot*()
  -> IpsecGetXfrmStates()/IpsecGetXfrmPolicies()
  -> NETLINK_XFRM dump

v15 sum_xfrm_errors()
  -> IpsecGetXfrmStatistics()
  -> direct /proc/net/xfrm_stat parser

v15 network show/validation
  -> IpsecGetInterfaces()/IpsecGetAddresses()/IpsecGetRoutes()
  -> NETLINK_ROUTE dump
```

## 11. 호환성과 제품 설계에 미치는 영향

- v15의 최소 기준은 strongSwan 5.8.4이며 list filtering의 버전 차이도 이미 경험했다 (`src/strongswan.c:592`). 신규 VICI client는 5.8.4에서 존재하는 command/key를 기준선으로 삼고 추가 key는 optional로 처리한다.
- v15는 IPv4 endpoint `/32` transport mode가 주 검증 범위다. 신규 API는 처음부터 IPv6와 일반 CIDR TS를 표현하되, 실제 1차 integration 검증은 v15와 동일한 IPv4/PSK 구성을 우선한다.
- NAT-T는 v15 설정에 별도 switch가 없고 charon 기본 동작에 의존한다. 신규 API에서도 IKE/NAT state machine을 구현하지 않는다.
- XFRM 조회와 route 조회는 Linux UAPI에만 의존하며 architecture-dependent packing을 직접 가정하지 않는다.
- charon socket 접근 권한과 Netlink dump 권한은 배포 환경 정책에 따라 다르므로 root를 무조건 요구하지 않고 `IPSEC_ERR_PERMISSION`으로 보고한다.

## 12. 라이선스 경계

- v15는 `libcharon`을 직접 링크하지 않고 `swanctl`을 외부 프로세스로 사용한다 (`README.md:28`).
- 신규 라이브러리는 strongSwan의 GPL `libstrongswan`, `libcharon`, GPL `libvici` 구현에 링크하지 않는다.
- VICI wire protocol은 독립 구현하고 Linux UAPI header를 사용한다.
- v15 자체 README는 오픈소스 라이선스를 부여하지 않고 all-rights-reserved라고 명시한다 (`README.md:402`). 상업용 배포 전 신규 저장소의 저작권자, 배포 라이선스, 제3자 고지 문구는 권리자가 확정해야 한다.
- 구현 코드에는 strongSwan GPL 소스 코드를 복사하지 않는다. 프로토콜 상호운용에 필요한 packet/field 정의는 공개 VICI 규격을 근거로 독립 작성한다.

## 13. Phase 1 완료 기록

### 변경한 파일

- 없음. v15 원본은 읽기 전용으로 분석했다.

### 새로 추가한 파일

- `docs/v15_analysis.md`

### 구현한 기능

- 없음. Phase 1은 분석 단계다.

### 아직 구현하지 않은 기능

- 전체 Native library, public API, VICI, XFRM, route, examples, tests

### 빌드 결과

- 신규 라이브러리: 아직 해당 없음
- v15: 제공된 `BUILD_VERIFICATION_V15.txt`에서 Linux strict build PASS를 확인했다. 현재 분석 호스트는 Windows이므로 이 단계에서 Linux 재빌드는 수행하지 않았다.

### 테스트 결과

- 정적 소스 조사 완료
- 외부 명령 의존성과 주요 호출 흐름 확인 완료
- 신규 코드 테스트는 아직 해당 없음

### 남아 있는 문제

- Phase 2에서 thread model, VICI connection 직렬화, async wait/event 정책, public ABI와 ownership을 확정해야 한다.
- strongSwan 5.8.4 VICI message field compatibility matrix를 설계 문서와 protocol unit fixture에 고정해야 한다.
- 상업 배포용 신규 프로젝트 라이선스 문구는 저작권자의 선택이 필요하다.
