# BSR 코드베이스 종합 분석 보고서
# BSR (Block Sync & Replication) Codebase Comprehensive Analysis Report

작성일: 2025-10-30

## 1. 프로젝트 개요 (Project Overview)

### 1.1 프로젝트 설명
BSR (Block Sync & Replication)은 네트워크를 통한 소프트웨어 기반 블록 복제를 구현하는 오픈소스 프로젝트입니다. 커널 레벨 복제 엔진을 기반으로 하며, Windows와 Linux 크로스 플랫폼 환경을 지원합니다.

**주요 특징:**
- DRBD 9.0 기반의 포크 프로젝트
- Windows (WDRBD) 및 Linux 크로스 플랫폼 지원
- 안정적인 1:N 동기화 로직 (Stable Sync)
- 파일시스템 사용 영역만 동기화하는 Fast Sync 기능
- 향상된 비동기 복제 성능 (Kernel TX Buffering)
- Passthrough 디스크 I/O 오류 정책

### 1.2 라이선스
- GPL v2

### 1.3 개발사
- Man Technology Inc. (http://www.mantech.co.kr/)
- Contact: bsr@mantech.co.kr

---

## 2. 코드베이스 구조 (Codebase Structure)

### 2.1 전체 디렉토리 구조

```
bsr/
├── bsr/                    # 커널 모듈 소스 코드 (62,597 LOC)
│   ├── bsr-kernel-compat/  # 커널 호환성 레이어
│   ├── bsr-lib/            # 커널 라이브러리
│   └── linux/              # Linux 특화 코드
├── bsr-headers/            # 공용 헤더 파일 (4,483 LOC)
│   ├── linux/              # Linux 헤더
│   └── windows/            # Windows 헤더
├── bsr-platform/           # 플랫폼별 코드 (12,794 LOC)
│   ├── linux/              # Linux 플랫폼 코드
│   │   └── bsrhk/          # BSR hook 모듈
│   └── windows/            # Windows 플랫폼 코드
│       ├── bsrfsflt/       # 파일시스템 필터
│       ├── bsrsvc/         # BSR 서비스
│       └── bsrvflt/        # 볼륨 필터
├── bsr-utils/              # 사용자 공간 유틸리티 (27,271 LOC)
│   ├── user/               # 사용자 도구 소스
│   │   ├── v9/             # BSR 9.x 도구
│   │   └── shared/         # 공유 유틸리티
│   ├── scripts/            # 헬퍼 스크립트
│   └── documentation/      # 문서
├── build/                  # 빌드 구성 및 스크립트
│   ├── linux/              # Linux 빌드
│   └── windows/            # Windows 빌드
└── debian/                 # Debian 패키징
```

### 2.2 코드 통계

| 구성요소 | 파일 타입 | 코드 라인 수 | 설명 |
|---------|----------|------------|------|
| 커널 모듈 (bsr/) | C | 62,597 | 핵심 복제 엔진 |
| 사용자 유틸리티 (bsr-utils/) | C | 27,271 | 관리 도구 |
| 플랫폼 코드 (bsr-platform/) | C/C++ | 12,794 | 플랫폼별 구현 |
| 헤더 파일 (bsr-headers/) | H | 4,483 | 공용 인터페이스 |
| **총계** | | **107,145** | |

**파일 타입 분포:**
- C 파일: 221개
- 헤더 파일: 102개
- C++ 파일: 12개
- 쉘 스크립트: 11개

---

## 3. 커널 모듈 분석 (Kernel Module Analysis)

### 3.1 주요 커널 소스 파일

| 파일명 | 크기 | 주요 기능 |
|-------|------|----------|
| `bsr_main.c` | 263K | 모듈 초기화, 장치 관리, 핵심 I/O 경로 |
| `bsr_receiver.c` | 403K | 네트워크 수신 처리, 프로토콜 핸들러 |
| `bsr_state.c` | 196K | 상태 머신, 역할 전환, 복제 상태 관리 |
| `bsr_sender.c` | 149K | 네트워크 송신, 비동기 복제 |
| `bsr_req.c` | 115K | 요청 처리, I/O 스케줄링 |
| `bsr_nl.c` | 238K | Netlink 통신, 사용자 공간 인터페이스 |
| `bsr_transport_tcp.c` | 83K | TCP 전송 레이어 구현 |
| `bsr_debugfs.c` | 66K | 디버그 인터페이스 |
| `bsr_actlog.c` | 63K | Activity Log 관리 |
| `bsr_bitmap.c` | 61K | 비트맵 관리, OOS 추적 |

### 3.2 핵심 데이터 구조

#### 3.2.1 계층 구조
```
bsr_resource (리소스)
    ├── bsr_device[] (장치/볼륨)
    │   └── 메이저/마이너 번호로 전역 접근 가능
    └── bsr_connection[] (연결)
        └── bsr_peer_device[][] (교차점)
```

#### 3.2.2 주요 구조체
- **bsr_resource**: 최상위 리소스 컨테이너
- **bsr_device**: 개별 복제 장치/볼륨
- **bsr_connection**: 피어 노드 연결
- **bsr_peer_device**: 장치와 연결의 교차점
- **bsr_request**: I/O 요청 추적

### 3.3 커널 아키텍처

#### 3.3.1 I/O 경로
1. **쓰기 요청 처리**:
   ```
   Block Layer → bsr_make_request() → bsr_req_make_private_bio()
   → Local Disk Write + Network Replication → Completion
   ```

2. **읽기 요청 처리**:
   ```
   Block Layer → bsr_make_request() → Local Disk Read → Completion
   ```

#### 3.3.2 상태 머신
- 역할 상태: Primary, Secondary, Unknown
- 디스크 상태: UpToDate, Inconsistent, Outdated, Diskless, Attaching, etc.
- 연결 상태: Connected, Connecting, StandAlone, Disconnecting, etc.
- 복제 상태: Established, SyncSource, SyncTarget, etc.

#### 3.3.3 동기화 메커니즘
- **Stable Sync**: 1:N 메시 토폴로지에서 방향성 제한
- **Fast Sync**: 파일시스템 사용 영역만 동기화 (NTFS, ReFS, ext, xfs)
- **Fast OV**: 온라인 검증 고속화
- **Activity Log (AL)**: 쓰기 활동 추적
- **Bitmap**: Out-of-Sync 영역 추적

#### 3.3.4 전송 레이어
- 추상화된 전송 인터페이스 (`bsr_transport`)
- TCP 구현 (`bsr_transport_tcp.c`)
- 커널 레벨 TX 버퍼링 지원
- RDMA 지원 가능성 (향후)

### 3.4 플랫폼별 구현

#### 3.4.1 Windows 특화 (`#ifdef _WIN`)
- NTFS/ReFS 파일시스템 통합
- Windows 커널 API 사용
- 필터 드라이버 아키텍처
- IOCTL 인터페이스

#### 3.4.2 Linux 특화 (`#ifdef _LIN`)
- ext/xfs 파일시스템 통합
- Linux 커널 API 사용
- Block Device 드라이버
- Netlink 인터페이스

---

## 4. 사용자 공간 유틸리티 (User-space Utilities)

### 4.1 주요 도구

#### 4.1.1 bsradm
- **역할**: 고수준 관리 도구
- **주요 파일**:
  - `bsradm_main.c` (105,181 LOC) - 메인 로직
  - `bsradm_parser.c` - 설정 파싱
  - `bsradm_adjust.c` - 설정 조정
  - `bsradm_postparse.c` - 후처리
- **기능**:
  - 리소스 up/down
  - 역할 변경 (primary/secondary)
  - 연결 관리
  - 설정 파일 파싱

#### 4.1.2 bsrsetup
- **역할**: 저수준 설정 도구
- **주요 파일**: `bsrsetup.c` (146,295 LOC)
- **기능**:
  - 장치 생성/삭제
  - 연결 설정
  - 파라미터 조정
  - 커널 모듈과 직접 통신

#### 4.1.3 bsrmeta
- **역할**: 메타데이터 관리
- **주요 파일**: `bsrmeta.c`
- **기능**:
  - 메타데이터 생성/검증
  - 비트맵 조작
  - Activity Log 관리

### 4.2 설정 관리
- **설정 파일**: `/etc/bsr.conf` (또는 `/etc/bsr.d/`)
- **파서**: Flex/Bison 기반 파서
- **스캐너**: `bsradm_scanner.fl`
- **파서**: `bsradm_parser.c/h`

### 4.3 통신 인터페이스
- **Linux**: Netlink Generic Netlink (Genl)
- **Windows**: IOCTL
- **프로토콜**: `bsr_genl_api.h`에 정의

---

## 5. 플랫폼별 코드 (Platform-specific Code)

### 5.1 Windows 플랫폼 (`bsr-platform/windows/`)

#### 5.1.1 bsrvflt (Volume Filter)
- 볼륨 필터 드라이버
- I/O 인터셉트 및 복제
- Fast Sync 지원

#### 5.1.2 bsrfsflt (Filesystem Filter)
- 파일시스템 필터 드라이버
- 파일시스템 메타데이터 추적
- NTFS/ReFS 통합

#### 5.1.3 bsrsvc (Service)
- Windows 서비스 구현
- 시스템 시작 시 자동 실행
- 리소스 관리

### 5.2 Linux 플랫폼 (`bsr-platform/linux/`)

#### 5.2.1 bsrhk (BSR Hook)
- 커널 훅 모듈
- 파일시스템 통합
- ext/xfs Fast Sync 지원

---

## 6. 빌드 시스템 (Build System)

### 6.1 Linux 빌드
- **Makefile**: GNU Make 기반
- **커널 모듈**: `make KDIR=/lib/modules/$(uname -r)/build`
- **사용자 도구**: Autotools (autoconf/automake)
  - `./autogen.sh`
  - `./configure`
  - `make`
- **패키징**:
  - RPM: `rpmbuild`
  - DEB: `debuild`

### 6.2 Windows 빌드
- **프로젝트**: Visual Studio (bsr.sln)
- **커널 드라이버**: WDK (Windows Driver Kit)
- **vcxproj 파일**: MSBuild 기반

### 6.3 크로스 플랫폼 빌드
- 조건부 컴파일: `#ifdef _WIN`, `#ifdef _LIN`
- 공용 헤더: `bsr-headers/`
- 호환성 레이어: `bsr-kernel-compat/`

---

## 7. 주요 기능 분석 (Key Features Analysis)

### 7.1 Stable Sync
**위치**: `bsr_state.c`, `bsr_receiver.c`

**개선 사항**:
- DRBD9의 불명확한 동기화 로직 재설계
- 1:N 메시 토폴로지에서 동기화 방향성 제한
- SyncSource 노드 명확화
- 역할 변경/스위치오버 시 프로토콜 기반 트리거

**구현**:
- 상태 전환 로직 강화
- 피어 상태 추적 개선
- 충돌 방지 메커니즘

### 7.2 Fast Sync
**위치**: `bsr-platform/windows/bsrfsflt/`, `bsr-platform/linux/bsrhk/`

**개선 사항**:
- 파일시스템 사용 영역만 동기화
- 전체 디스크 대비 동기화 시간 대폭 단축
- Windows: NTFS, ReFS 지원
- Linux: ext, xfs 지원 (포팅 중)

**구현**:
- 파일시스템 필터/훅을 통한 사용 영역 추적
- 비트맵 최적화
- 선택적 블록 동기화

### 7.3 Fast OV (Online Verification)
**위치**: `bsr_receiver.c`

**개선 사항**:
- 파일시스템 사용 영역만 검증
- 빠른 일관성 검사

### 7.4 Kernel TX Buffering
**위치**: `bsr_sender.c`, `bsr_send_buf.c` (조건부)

**개선 사항**:
- Linux에서 커널 레벨 TX 버퍼링
- DRX 프록시 없이 장거리 복제 가능
- 비동기 복제 성능 향상

**구현**:
- 송신 버퍼 관리
- 흐름 제어
- 혼잡 제어

### 7.5 개선된 엔진 로직

#### 7.5.1 복제 요청 분리
**문제**: DRBD9에서 저대역폭 환경에서 로컬 I/O 성능 저하

**해결**:
- 복제 요청을 별도로 관리
- 로컬 I/O와 네트워크 복제 분리
- 저대역폭에서도 로컬 I/O 성능 유지

#### 7.5.2 AL 및 Resync LRU 최적화
**문제**: Activity Log와 Resync LRU 간 경쟁 및 간섭

**해결**:
- AL 병목 현상 최소화
- Resync LRU와 AL 간 상호 간섭 방지
- 로컬 I/O 영향 감소

### 7.6 Passthrough Policy
**위치**: `bsr_main.c`, `bsr_req.c`

**개선 사항**:
- 기존 detach 정책의 대안
- 디스크 I/O 오류 시 파일시스템에 재시도 기회 제공
- diskless 모드의 단점 보완
- HA 운영 유연성 향상

**구현**:
- I/O 오류 처리 로직 개선
- detach 대신 passthrough 옵션
- 파일시스템 레벨 복구 가능

### 7.7 Timeout 처리
**위치**: 전역적으로 적용

**개선 사항**:
- DRBD의 엄격한 처리 로직으로 인한 hang 이슈 해결
- 적절한 타임아웃을 통한 예외 처리
- 운영 안정성 향상

---

## 8. 코드 품질 분석 (Code Quality Analysis)

### 8.1 강점

1. **잘 구조화된 아키텍처**:
   - 명확한 계층 구조 (리소스 → 장치 → 연결)
   - 모듈화된 컴포넌트
   - 추상화된 전송 레이어

2. **크로스 플랫폼 설계**:
   - 조건부 컴파일을 통한 플랫폼 분리
   - 공용 헤더 및 호환성 레이어
   - 플랫폼별 최적화

3. **포괄적인 에러 처리**:
   - 타임아웃 메커니즘
   - Passthrough 정책
   - 상태 복구 로직

4. **성능 최적화**:
   - Fast Sync/OV
   - Kernel TX Buffering
   - AL/LRU 최적화

5. **문서화**:
   - 코드 내 주석
   - README 파일
   - 기술 문서

### 8.2 개선 가능 영역

1. **코드 복잡도**:
   - 일부 파일이 매우 큼 (bsr_receiver.c: 403K)
   - 함수 분리 및 리팩토링 필요
   - 조건부 컴파일로 인한 복잡성

2. **테스트 인프라**:
   - 자동화된 테스트 스위트 부족
   - 단위 테스트 부재
   - 통합 테스트 제한적

3. **문서화**:
   - API 문서 부족
   - 사용자 가이드 보완 필요
   - 아키텍처 문서 업데이트

4. **코드 일관성**:
   - 명명 규칙 통일 필요
   - 코딩 스타일 가이드 적용
   - 주석 일관성

### 8.3 보안 고려사항

1. **입력 검증**:
   - 사용자 입력 검증
   - 네트워크 데이터 검증
   - 버퍼 오버플로우 방지

2. **권한 관리**:
   - 커널 모드 권한 필요
   - 관리자 권한 요구

3. **암호화**:
   - 네트워크 전송 암호화 옵션
   - 인증 메커니즘

---

## 9. 의존성 및 호환성 (Dependencies and Compatibility)

### 9.1 Linux 의존성
- **커널 버전**: 3.x ~ 5.x+ (호환성 레이어 통해)
- **빌드 도구**: gcc, make, autotools
- **라이브러리**: libc, libcrypto (선택)
- **파일시스템**: ext2/3/4, xfs, btrfs (Fast Sync: ext, xfs)

### 9.2 Windows 의존성
- **OS 버전**: Windows Server 2012+ / Windows 7+
- **빌드 도구**: Visual Studio, WDK
- **파일시스템**: NTFS, ReFS (Fast Sync 지원)

### 9.3 호환성
- **DRBD 호환성**: 프로토콜 레벨에서 부분 호환
- **하위 호환성**: 메타데이터 포맷 호환
- **업그레이드 경로**: DRBD에서 BSR로 마이그레이션 가능

---

## 10. 개발 프로세스 (Development Process)

### 10.1 버전 관리
- **Git**: GitHub 저장소
- **브랜치 전략**: Feature branches, develop, master
- **태그**: 릴리스 버전 태깅

### 10.2 빌드 및 릴리스
- **CI/CD**: 자동화 빌드 시스템 (제한적)
- **패키징**: RPM, DEB, MSI
- **배포**: GitHub Releases

### 10.3 기여 가이드
- GPL v2 라이선스 준수
- 코드 리뷰 프로세스
- 이슈 트래킹

---

## 11. 성능 특성 (Performance Characteristics)

### 11.1 복제 모드
- **프로토콜 A** (비동기): 최고 성능, 데이터 손실 가능
- **프로토콜 B** (반동기): 균형
- **프로토콜 C** (동기): 최고 안정성, 성능 저하

### 11.2 최적화 포인트
- **Kernel TX Buffering**: 장거리 복제 성능 향상
- **AL 최적화**: 로컬 I/O 성능 개선
- **Fast Sync**: 동기화 시간 단축
- **Resync LRU**: 동기화 오버헤드 감소

### 11.3 벤치마크 영역
- 로컬 I/O 처리량
- 네트워크 복제 대역폭
- 동기화 속도
- CPU 사용률
- 메모리 사용량

---

## 12. 운영 고려사항 (Operational Considerations)

### 12.1 HA 환경
- **자동 페일오버**: Pacemaker, WSFC 통합
- **Split-brain 방지**: Fencing 메커니즘
- **쿼럼**: 다수결 투표

### 12.2 모니터링
- **디버그 인터페이스**: `/sys/kernel/debug/bsr/`
- **상태 확인**: `bsradm status`
- **로그**: 커널 로그, 응용 로그

### 12.3 문제 해결
- **OOS 추적**: 비트맵 분석
- **성능 튜닝**: 파라미터 조정
- **복구 절차**: 수동 복구, 자동 복구

---

## 13. 향후 방향 (Future Directions)

### 13.1 계획된 기능
- Fast Sync Linux 포팅 완료
- 추가 파일시스템 지원 (btrfs, ZFS)
- RDMA 전송 레이어
- 암호화 강화
- 클라우드 통합

### 13.2 개선 영역
- 테스트 자동화
- 문서화 강화
- 성능 최적화 지속
- 커뮤니티 구축

---

## 14. 결론 (Conclusion)

BSR은 DRBD를 기반으로 한 성숙하고 안정적인 블록 복제 솔루션입니다. 주요 강점은 다음과 같습니다:

### 14.1 핵심 장점
1. **크로스 플랫폼 지원**: Windows와 Linux 모두 지원
2. **안정성**: DRBD9의 문제점 해결 (Stable Sync, 타임아웃 처리)
3. **성능**: Fast Sync, Kernel TX Buffering, AL/LRU 최적화
4. **유연성**: Passthrough 정책, 다양한 복제 프로토콜
5. **엔터프라이즈 준비**: HA 환경에서 검증됨

### 14.2 기술적 우수성
- **잘 설계된 아키텍처**: 모듈화, 계층화, 추상화
- **코드 품질**: 62만 라인 이상의 잘 유지보수된 코드
- **플랫폼 적응**: 각 플랫폼의 최적 기능 활용

### 14.3 비즈니스 가치
- **검증된 안정성**: 수년간 엔터프라이즈 HA 환경에서 사용
- **비용 효율성**: 오픈소스, 하드웨어 독립적
- **지속적인 개발**: 활발한 유지보수 및 기능 추가

BSR은 고가용성이 요구되는 환경에서 신뢰할 수 있는 블록 복제 솔루션으로, DRBD의 문제점을 해결하고 더 나은 성능과 안정성을 제공합니다.

---

## 15. 참고 자료 (References)

### 15.1 문서
- README.md - 프로젝트 개요
- bsr-utils/README.md - 사용자 도구 가이드
- bsr/README - 커널 모듈 아키텍처
- ChangeLog - 변경 이력

### 15.2 소스 코드
- bsr/ - 커널 모듈
- bsr-utils/ - 사용자 도구
- bsr-platform/ - 플랫폼별 코드
- bsr-headers/ - 공용 헤더

### 15.3 외부 리소스
- Man Technology Inc.: http://www.mantech.co.kr/
- 이메일 문의: bsr@mantech.co.kr
- GitHub 저장소: https://github.com/mantechnology/bsr

---

**분석자**: GitHub Copilot Agent
**분석 일시**: 2025-10-30
**버전**: 커밋 47a41eb 기준
