# Native IPsec library 단계별 상태

기록일: 2026-08-12

## Phase 1 — Existing code analysis

상태: 완료

- 추가 파일: `docs/v15_analysis.md`
- v15의 strongSwan command 실행, XFRM text parser, config/proposal/PSK/SA
  wait 및 capture/UDP/barrier/matrix/report 모듈을 실제 소스로 분석했다.
- 재사용 가능한 의미(A), Native 재구현(B), 시험 전용 제거(C)로 분류했다.
- v15 소스는 라이선스 문구에 따라 복사하지 않고 동작 의미만 분석했다.

## Phase 2 — Architecture design

상태: 완료

- 추가 파일: `docs/native_architecture.md`, `docs/public_api.md`
- 별도 charon + 독립 VICI client + read-only NETLINK_XFRM +
  `/proc/net/xfrm_stat` + read-only NETLINK_ROUTE로 설계했다.
- context/thread/ownership/error/logging/licensing boundary를 문서화했다.

## Phase 3 — Public API

상태: 완료

- 추가 파일: `include/ipsec.h`, `include/ipsec_types.h`,
  `include/ipsec_error.h`
- opaque context, C/C++ linkage, typed list/free API, error enum,
  logger callback을 제공한다.
- 1차 credential 구현은 PSK이며 certificate/private key/CA/EAP는 확장 범위다.

## Phase 4 — VICI transport/protocol/operations

상태: 구현 및 교차 컴파일 완료, live charon 검증 대기

- Unix Domain Socket connect/timeout/partial I/O 및 다음 호출 시 reconnect
- 512 KiB packet cap, network byte order, strict element nesting/length 검사
- connection load/unload/list, PSK load/credential clear
- IKE/CHILD initiate/terminate/rekey/wait
- IKE/CHILD/algorithm/daemon structured status
- 5.8.4 VICI encode fixture와 malformed packet 단위 테스트

## Phase 5 — NETLINK_XFRM

상태: 구현 및 합성 message 테스트 컴파일 완료, Linux runtime 실행 대기

- `XFRM_MSG_GETSA`, `XFRM_MSG_GETPOLICY` dump만 전송한다.
- SA/policy 생성·삭제 API는 없다.
- state/policy base structure 및 attribute boundary를 검사한다.
- unknown attribute는 무시하고 truncated/malformed attribute는 거부한다.

## Phase 6 — XFRM statistics

상태: 구현 및 단위 테스트 실행 완료

- `/proc/net/xfrm_stat`을 `open/read`로 직접 조회한다.
- key/value parser는 unknown key를 허용하고 known key duplicate와 invalid
  value를 거부한다.

## Phase 7 — NETLINK_ROUTE

상태: 구현 및 합성 message 테스트 컴파일 완료, Linux runtime 실행 대기

- RTM_GETLINK/GETADDR/GETROUTE read-only dump를 구현했다.
- IPv4/IPv6, interface carrier/MTU/link address, address prefix/scope,
  route gateway/source/OIF/metric/table/protocol/scope를 구조화한다.
- 외부 `ip` command를 사용하지 않는다.

## Phase 8 — Application and integration test

상태: 구현 및 양 architecture 링크 완료, peer 연동 실행 대기

- `app/`
- `tests/integration/test_live_ipsec.c`
- integration test는 dedicated charon에서 connection/PSK load, initiate,
  IKE/CHILD/XFRM show, terminate, cleanup 순서로 동작한다.

## 빌드 및 정적 검증 결과

- x86_64-linux-gnu: 전체 object, `.a`, `.so`, application, unit/integration
  test binaries 성공
- aarch64-linux-gnu: 동일 범위 성공
- flags: C11, `-Wall -Wextra -Wpedantic -Werror`, PIC
- ELF dependency: libc, pthread/target runtime loader만 존재
- `libstrongswan`, `libcharon`, GPL `libvici` dependency/symbol 없음
- source scan: `system`, `popen`, `fork`, `exec*` 호출 없음
- source scan: 금지 command 문자열/실행 경로 없음

## 아직 수행하지 못한 검증

- Ubuntu/PetaLinux 실제 charon 5.8.4+ VICI socket 연동
- 실제 peer와 PSK IKEv2/IKE SA/CHILD SA/PFS/ESN/NAT-T/rekey/terminate
- 실제 kernel의 XFRM/route dump와 장비 관측값 비교
- target GCC/CMake/Make native build 및 장시간/동시 호출 시험

이 항목들은 코드 미구현이 아니라 현재 Windows 개발 host에 charon과 Linux
kernel XFRM이 없어 남은 target integration verification이다. 실행 절차는
`tests/integration/README.md`에 기록했다.

## 상용 배포 전 남은 조직 결정

- 저작권자가 `libipsec`의 최종 proprietary 또는 open-source
  license text를 추가해야 한다.
- 법무 검토에서 protocol interoperability, Linux UAPI header 사용,
  strongSwan 별도 프로세스 배포/고지 경계를 최종 확인해야 한다.
