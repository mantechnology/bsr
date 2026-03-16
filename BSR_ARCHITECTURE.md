# BSR 아키텍처 상세 분석
# BSR Architecture Detailed Analysis

## 1. 시스템 아키텍처 개요

### 1.1 전체 시스템 레이어

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│            (File System, Database, etc.)                     │
└─────────────────────────────────────────────────────────────┘
                          ↓↑
┌─────────────────────────────────────────────────────────────┐
│                   File System Layer                          │
│              (NTFS, ReFS, ext4, xfs, etc.)                   │
└─────────────────────────────────────────────────────────────┘
                          ↓↑
┌─────────────────────────────────────────────────────────────┐
│                   BSR Block Device                           │
│         ┌─────────────────────────────────────┐            │
│         │     BSR Kernel Module (bsr.ko)      │            │
│         │  ┌──────────┬──────────┬──────────┐ │            │
│         │  │ Request  │  State   │ Network  │ │            │
│         │  │ Handler  │  Machine │ Transport│ │            │
│         │  └──────────┴──────────┴──────────┘ │            │
│         └─────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────┘
                    ↓↑                    ↓↑
        ┌──────────────────┐    ┌────────────────┐
        │  Physical Disk   │    │    Network     │
        │   (Local I/O)    │    │  (Replication) │
        └──────────────────┘    └────────────────┘
                                        ↓↑
                                ┌───────────────┐
                                │  Peer Node    │
                                │  (BSR Device) │
                                └───────────────┘
```

## 2. 커널 모듈 내부 아키텍처

### 2.1 주요 서브시스템

```
┌───────────────────────────────────────────────────────────────┐
│                    BSR Kernel Module                          │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              I/O Request Processing                      │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐            │ │
│  │  │ make_req │→ │  Local   │→ │ Network  │            │ │
│  │  │          │  │   I/O    │  │  Send    │            │ │
│  │  └──────────┘  └──────────┘  └──────────┘            │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              State Management                            │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐            │ │
│  │  │  Role    │  │  Disk    │  │Connection│            │ │
│  │  │  State   │  │  State   │  │  State   │            │ │
│  │  └──────────┘  └──────────┘  └──────────┘            │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Network Transport                           │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐            │ │
│  │  │ Receiver │  │  Sender  │  │   TCP    │            │ │
│  │  │  Thread  │  │  Thread  │  │ Protocol │            │ │
│  │  └──────────┘  └──────────┘  └──────────┘            │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Synchronization                             │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐            │ │
│  │  │ Activity │  │  Bitmap  │  │  Resync  │            │ │
│  │  │   Log    │  │          │  │   LRU    │            │ │
│  │  └──────────┘  └──────────┘  └──────────┘            │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Metadata Management                         │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐            │ │
│  │  │ Meta     │  │  GI      │  │  Peer    │            │ │
│  │  │  Data    │  │ (UUID)   │  │   MD     │            │ │
│  │  └──────────┘  └──────────┘  └──────────┘            │ │
│  └─────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

### 2.2 데이터 흐름 (쓰기 경로)

```
Application Write
      ↓
┌─────────────────┐
│ File System     │
└─────────────────┘
      ↓
┌─────────────────┐
│ Block Layer     │
└─────────────────┘
      ↓
┌─────────────────┐
│ bsr_make_request│ ← Entry point
└─────────────────┘
      ↓
┌─────────────────┐
│ Create Request  │
│ (bsr_request)   │
└─────────────────┘
      ↓
    ┌─┴─┐
    │ ? │ Check State
    └─┬─┘
      ↓
  ┌───────┐
  │Primary│?
  └───┬───┘
      │
      ├─Yes→┌──────────────┐
      │     │ Local Write  │
      │     └──────────────┘
      │           ↓
      │     ┌──────────────┐
      │     │Update AL/BM  │
      │     └──────────────┘
      │           ↓
      │     ┌──────────────┐
      │     │Network Send  │
      │     └──────────────┘
      │           ↓
      │     ┌──────────────┐
      │     │Wait for ACK  │ (Protocol dependent)
      │     └──────────────┘
      │           ↓
      │     ┌──────────────┐
      │     │  Complete    │
      │     └──────────────┘
      │
      └─No→┌──────────────┐
            │   Return     │
            │   Error      │
            └──────────────┘
```

### 2.3 네트워크 프로토콜 레이어

```
┌──────────────────────────────────────────────────────────┐
│                 BSR Protocol Stack                        │
│                                                           │
│  Application Level                                        │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Command/Control (via Netlink/IOCTL)                │ │
│  └────────────────────────────────────────────────────┘ │
│                        ↓↑                                 │
│  BSR Protocol Level                                       │
│  ┌────────────────────────────────────────────────────┐ │
│  │ BSR Protocol Messages:                             │ │
│  │  - Data Packets (P_DATA)                           │ │
│  │  - Acknowledgments (P_RS_WRITE_ACK)                │ │
│  │  - State Changes (P_STATE)                         │ │
│  │  - Synchronization (P_SYNC_PARAM)                  │ │
│  │  - Barrier (P_BARRIER)                             │ │
│  └────────────────────────────────────────────────────┘ │
│                        ↓↑                                 │
│  Transport Abstraction                                    │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsr_transport interface                            │ │
│  │  - send()                                          │ │
│  │  - recv()                                          │ │
│  │  - connect()                                       │ │
│  └────────────────────────────────────────────────────┘ │
│                        ↓↑                                 │
│  Concrete Transport                                       │
│  ┌────────────────────────────────────────────────────┐ │
│  │ TCP Implementation (bsr_transport_tcp)             │ │
│  │  - Socket management                               │ │
│  │  - Buffer management                               │ │
│  │  - Flow control                                    │ │
│  └────────────────────────────────────────────────────┘ │
│                        ↓↑                                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │ TCP/IP Stack (Kernel)                              │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

## 3. 상태 머신

### 3.1 역할 상태 전환

```
         ┌──────────┐
         │ Unknown  │
         └─────┬────┘
               │
        ┌──────┴──────┐
        │             │
        ↓             ↓
   ┌─────────┐   ┌─────────┐
   │Secondary│   │ Primary │
   └────┬────┘   └────┬────┘
        │             │
        └──────┬──────┘
               │
        ┌──────┴──────┐
        │  demotion   │
        │  promotion  │
        └─────────────┘
```

### 3.2 디스크 상태 전환

```
                    ┌────────────┐
                    │  Diskless  │
                    └──────┬─────┘
                           │
                           ↓
                    ┌────────────┐
                    │ Attaching  │
                    └──────┬─────┘
                           │
                    ┌──────┴──────┐
                    │             │
                    ↓             ↓
             ┌────────────┐  ┌────────────┐
             │Negotiating │  │   Failed   │
             └──────┬─────┘  └────────────┘
                    │
         ┌──────────┼──────────┐
         │          │          │
         ↓          ↓          ↓
    ┌────────┐ ┌────────┐ ┌────────┐
    │Up-to-  │ │Consist-│ │Incons- │
    │ Date   │ │ ent    │ │istent  │
    └────────┘ └────────┘ └───┬────┘
         │          │          │
         └──────────┼──────────┘
                    │
                    ↓
             ┌────────────┐
             │  Outdated  │
             └────────────┘
```

### 3.3 연결 상태 전환

```
    ┌────────────┐
    │ StandAlone │
    └──────┬─────┘
           │
           ↓
    ┌────────────┐
    │Unconnected │
    └──────┬─────┘
           │
           ↓
    ┌────────────┐
    │ Connecting │
    └──────┬─────┘
           │
           ↓
    ┌────────────┐
    │  Connected │
    └──────┬─────┘
           │
    ┌──────┴───────┐
    │              │
    ↓              ↓
┌─────────┐  ┌──────────────┐
│Disconn- │  │ Replication  │
│ecting   │  │  States      │
└─────────┘  └──────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
        ↓           ↓           ↓
   ┌────────┐  ┌────────┐  ┌────────┐
   │ Sync   │  │ Sync   │  │Paused  │
   │ Source │  │ Target │  │ Sync   │
   └────────┘  └────────┘  └────────┘
```

## 4. 동기화 메커니즘

### 4.1 Stable Sync 아키텍처

```
┌──────────────────────────────────────────────────────────┐
│              1:N Mesh Topology                            │
│                                                           │
│    Node A (Primary)                                       │
│       ↓    ↓    ↓                                        │
│       │    │    │                                        │
│   ┌───┼────┼────┼───┐                                   │
│   │   │    │    │   │                                   │
│   ↓   ↓    ↓    ↓   ↓                                   │
│ Node B  Node C  Node D  Node E                           │
│ (Sec)   (Sec)   (Sec)   (Sec)                           │
│                                                           │
│ Synchronization Direction:                                │
│  - Primary → Secondary (Established)                      │
│  - On role change: Update sync direction                  │
│  - Clear SyncSource designation                           │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Fast Sync 메커니즘

```
┌──────────────────────────────────────────────────────────┐
│               Fast Sync Process                           │
│                                                           │
│  Traditional Sync:                                        │
│  ┌────────────────────────────────────────────────────┐ │
│  │ [====== Full Disk Scan ======]                     │ │
│  │  └─ Sync all blocks (used + unused)                │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Fast Sync:                                               │
│  ┌────────────────────────────────────────────────────┐ │
│  │ [==== File System Used Blocks Only ====]           │ │
│  │  └─ Skip unused blocks (much faster)               │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Implementation:                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Filesystem Filter/Hook                             │ │
│  │   ↓                                                 │ │
│  │ Track Used Block Ranges                            │ │
│  │   ↓                                                 │ │
│  │ Generate Selective Bitmap                          │ │
│  │   ↓                                                 │ │
│  │ Sync Only Marked Blocks                            │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Supported Filesystems:                                   │
│  - Windows: NTFS, ReFS                                    │
│  - Linux: ext4, xfs (in progress)                         │
└──────────────────────────────────────────────────────────┘
```

### 4.3 Activity Log (AL) 구조

```
┌──────────────────────────────────────────────────────────┐
│                  Activity Log (AL)                        │
│                                                           │
│  Purpose: Track recently written areas for fast recovery  │
│                                                           │
│  Structure:                                               │
│  ┌────────────────────────────────────────────────────┐ │
│  │ AL Header                                          │ │
│  ├────────────────────────────────────────────────────┤ │
│  │ AL Extents (Hot Write Areas)                       │ │
│  │  ┌──────────┐                                      │ │
│  │  │ Extent 1 │  ← Recently written area             │ │
│  │  ├──────────┤                                      │ │
│  │  │ Extent 2 │                                      │ │
│  │  ├──────────┤                                      │ │
│  │  │   ...    │                                      │ │
│  │  ├──────────┤                                      │ │
│  │  │ Extent N │                                      │ │
│  │  └──────────┘                                      │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Operations:                                              │
│  - Write: Add extent to AL                                │
│  - Complete: Mark as synced                               │
│  - Recovery: Resync only AL extents                       │
│                                                           │
│  Optimization:                                            │
│  - LRU cache for hot extents                              │
│  - Reduced interference with Resync LRU                   │
└──────────────────────────────────────────────────────────┘
```

### 4.4 Bitmap 구조

```
┌──────────────────────────────────────────────────────────┐
│                     Bitmap Structure                      │
│                                                           │
│  Purpose: Track Out-of-Sync (OOS) blocks                  │
│                                                           │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Disk Blocks:                                       │ │
│  │ [■][■][□][■][□][□][■][■][□][■]...                 │ │
│  │  ■ = Out-of-Sync                                   │ │
│  │  □ = In-Sync                                       │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Bitmap Metadata:                                         │
│  ┌────────────────────────────────────────────────────┐ │
│  │ - Granularity: 4KB (default)                       │ │
│  │ - Location: On-disk metadata area                  │ │
│  │ - Per-peer bitmap for N-way replication            │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Operations:                                              │
│  - Set: Mark block as OOS on write                        │
│  - Clear: Mark as synced after replication                │
│  - Scan: Find OOS ranges for resync                       │
│                                                           │
│  Fast Sync Integration:                                   │
│  - Bitmap + FS used blocks = Selective sync               │
└──────────────────────────────────────────────────────────┘
```

## 5. 플랫폼별 아키텍처

### 5.1 Linux 아키텍처

```
┌──────────────────────────────────────────────────────────┐
│                   Linux Platform                          │
│                                                           │
│  User Space:                                              │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsradm  │  bsrsetup  │  bsrmeta                    │ │
│  └────────────────────────────────────────────────────┘ │
│         ↓↑            ↓↑                                  │
│  ┌────────────────────────────────────────────────────┐ │
│  │       Netlink (Generic Netlink)                    │ │
│  └────────────────────────────────────────────────────┘ │
│         ↓↑                                                │
│  Kernel Space:                                            │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsr.ko (Kernel Module)                             │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │ Block Device Driver                          │ │ │
│  │  │  - register_blkdev()                         │ │ │
│  │  │  - make_request_fn()                         │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │ Network Layer                                │ │ │
│  │  │  - TCP sockets                               │ │ │
│  │  │  - Kernel threads (receiver, sender)         │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────┘ │
│         ↓↑            ↓↑                                  │
│  ┌────────────┐  ┌──────────────┐                       │
│  │ Block Dev  │  │   TCP/IP     │                       │
│  └────────────┘  └──────────────┘                       │
│                                                           │
│  Fast Sync Support:                                       │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsrhk.ko (BSR Hook Module)                         │ │
│  │  - Filesystem hooks (ext4, xfs)                    │ │
│  │  - Track used block ranges                         │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### 5.2 Windows 아키텍처

```
┌──────────────────────────────────────────────────────────┐
│                  Windows Platform                         │
│                                                           │
│  User Space:                                              │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsradm.exe │ bsrsetup.exe │ bsrmeta.exe            │ │
│  └────────────────────────────────────────────────────┘ │
│         ↓↑            ↓↑                                  │
│  ┌────────────────────────────────────────────────────┐ │
│  │          IOCTL Interface                           │ │
│  └────────────────────────────────────────────────────┘ │
│         ↓↑                                                │
│  Kernel Space:                                            │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsr.sys (Kernel Driver)                            │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │ Volume Filter Driver                         │ │ │
│  │  │  - IRP_MJ_READ/WRITE intercept               │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────┘ │
│         ↓↑                                                │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsrvflt.sys (Volume Filter)                        │ │
│  │  - Volume I/O interception                         │ │
│  │  - Replication logic                               │ │
│  └────────────────────────────────────────────────────┘ │
│         ↓↑                                                │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsrfsflt.sys (Filesystem Filter)                   │ │
│  │  - NTFS/ReFS integration                           │ │
│  │  - Track used block ranges (Fast Sync)             │ │
│  └────────────────────────────────────────────────────┘ │
│         ↓↑            ↓↑                                  │
│  ┌────────────┐  ┌──────────────┐                       │
│  │ Disk Stack │  │   TCP/IP     │                       │
│  └────────────┘  └──────────────┘                       │
│                                                           │
│  Service:                                                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsrsvc.exe (Windows Service)                       │ │
│  │  - Auto-start on boot                              │ │
│  │  - Resource management                             │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

## 6. 성능 최적화 아키텍처

### 6.1 Request 분리 아키텍처

```
┌──────────────────────────────────────────────────────────┐
│            Separated Request Management                   │
│                                                           │
│  Original DRBD Issue:                                     │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Local I/O ←→ Network Replication                   │ │
│  │   (Coupled, bottleneck at low bandwidth)           │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  BSR Solution:                                            │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Local I/O Queue                                    │ │
│  │   ↓                                                 │ │
│  │ [Fast Path] → Local Disk → Complete                │ │
│  └────────────────────────────────────────────────────┘ │
│                        ∥ (parallel)                       │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Replication Queue                                  │ │
│  │   ↓                                                 │ │
│  │ [Async Path] → Network → Peer ACK                  │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Benefits:                                                │
│  - Local I/O not affected by network latency              │
│  - Better performance at low bandwidth                    │
└──────────────────────────────────────────────────────────┘
```

### 6.2 AL/Resync LRU 최적화

```
┌──────────────────────────────────────────────────────────┐
│          AL and Resync LRU Optimization                   │
│                                                           │
│  Original DRBD Issue:                                     │
│  ┌────────────────────────────────────────────────────┐ │
│  │ AL ←→ Resync LRU                                   │ │
│  │  (Cross-reference, interference, bottleneck)       │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  BSR Solution:                                            │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Activity Log (AL)                                  │ │
│  │  - Minimized bottleneck                            │ │
│  │  - Fast update path                                │ │
│  │  - No interference with Resync                     │ │
│  └────────────────────────────────────────────────────┘ │
│                        ∥ (independent)                    │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Resync LRU                                         │ │
│  │  - Separate management                             │ │
│  │  - Optimized for sync operations                   │ │
│  │  - No competition with AL                          │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Benefits:                                                │
│  - Reduced local I/O bottleneck                           │
│  - Faster synchronization                                 │
│  - Stable concurrent replication and sync                 │
└──────────────────────────────────────────────────────────┘
```

### 6.3 Kernel TX Buffering

```
┌──────────────────────────────────────────────────────────┐
│            Kernel TX Buffering Architecture               │
│                                                           │
│  Traditional Approach:                                    │
│  ┌────────────────────────────────────────────────────┐ │
│  │ BSR → [Small Buffer] → Network → Peer              │ │
│  │   (High latency on long-distance replication)      │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  BSR Kernel TX Buffering:                                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │ BSR → [Large Kernel Buffer] → Network → Peer       │ │
│  │         ↑                                           │ │
│  │     Absorbs bursts                                 │ │
│  │     Smooth transmission                            │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Components:                                              │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Send Buffer Manager                                │ │
│  │  - Dynamic buffer allocation                       │ │
│  │  - Flow control                                    │ │
│  │  - Congestion management                           │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Benefits:                                                │
│  - Better async replication performance                   │
│  - No need for DRX proxy on Linux                         │
│  - Handles long-distance replication efficiently          │
└──────────────────────────────────────────────────────────┘
```

## 7. 오류 처리 아키텍처

### 7.1 Passthrough Policy

```
┌──────────────────────────────────────────────────────────┐
│              Disk I/O Error Handling                      │
│                                                           │
│  Traditional Detach Policy:                               │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Disk I/O Error → Detach Disk → Diskless Mode       │ │
│  │   (Too aggressive, inflexible for HA)              │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  BSR Passthrough Policy:                                  │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Disk I/O Error                                     │ │
│  │   ↓                                                 │ │
│  │ Pass error to File System                          │ │
│  │   ↓                                                 │ │
│  │ File System Retry Logic                            │ │
│  │   ↓                                                 │ │
│  │ ┌─────────┐                                        │ │
│  │ │ Success?│                                        │ │
│  │ └────┬────┘                                        │ │
│  │      │                                              │ │
│  │   Yes│   No                                        │ │
│  │      ↓     ↓                                        │ │
│  │  Continue  FS handles error                        │ │
│  │            (remount ro, etc.)                      │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Configuration:                                           │
│  - on-io-error: passthrough | detach | call-local-io-error│
│  - Flexible error handling per deployment needs           │
│                                                           │
│  Benefits:                                                │
│  - More graceful error handling                           │
│  - Opportunity for recovery                               │
│  - Better for HA environments                             │
└──────────────────────────────────────────────────────────┘
```

### 7.2 Timeout 아키�ecture

```
┌──────────────────────────────────────────────────────────┐
│                Timeout Management                         │
│                                                           │
│  DRBD Issue:                                              │
│  ┌────────────────────────────────────────────────────┐ │
│  │ No timeout handling → Hang issues                  │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  BSR Timeout Strategy:                                    │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Network Operations                                 │ │
│  │   ↓                                                 │ │
│  │ [Timeout Timer]                                    │ │
│  │   ↓                                                 │ │
│  │ ┌──────────┐                                       │ │
│  │ │ Complete │                                       │ │
│  │ │ in time? │                                       │ │
│  │ └────┬─────┘                                       │ │
│  │      │                                              │ │
│  │   Yes│   No                                        │ │
│  │      ↓     ↓                                        │ │
│  │  Success  Timeout Handler                          │ │
│  │            - Close connection                      │ │
│  │            - Change state                          │ │
│  │            - Log error                             │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Configurable Timeouts:                                   │
│  - connect-timeout                                        │
│  - ping-timeout                                           │
│  - ko-count (keepalive)                                   │
│                                                           │
│  Benefits:                                                │
│  - Prevent indefinite hangs                               │
│  - Faster failure detection                               │
│  - Better system stability                                │
└──────────────────────────────────────────────────────────┘
```

## 8. 배포 아키텍처

### 8.1 고가용성 (HA) 구성

```
┌──────────────────────────────────────────────────────────┐
│              High Availability Configuration              │
│                                                           │
│  Active-Passive (2-Node):                                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Node A (Primary, Active)                           │ │
│  │   ↓↑ BSR Replication                               │ │
│  │ Node B (Secondary, Standby)                        │ │
│  │                                                     │ │
│  │ HA Manager: Pacemaker/WSFC                         │ │
│  │  - Monitor health                                  │ │
│  │  - Automatic failover                              │ │
│  │  - Resource management                             │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Active-Active (2-Node with Shared-Nothing):              │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Node A (Primary for Resource 1)                    │ │
│  │   ↓↑ BSR Replication                               │ │
│  │ Node B (Primary for Resource 2)                    │ │
│  │                                                     │ │
│  │ Each node serves different resources               │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Multi-Node (3+ Nodes):                                   │
│  ┌────────────────────────────────────────────────────┐ │
│  │      Node A (Primary)                              │ │
│  │        ↙  ↓  ↘                                     │ │
│  │       ↓   ↓   ↓                                    │ │
│  │   Node B Node C Node D                             │ │
│  │   (Sec)  (Sec)  (Sec)                              │ │
│  │                                                     │ │
│  │ Quorum-based decision making                       │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### 8.2 재해 복구 (DR) 구성

```
┌──────────────────────────────────────────────────────────┐
│          Disaster Recovery Configuration                  │
│                                                           │
│  Synchronous Local + Asynchronous Remote:                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Primary Site                                       │ │
│  │ ┌──────────┐ Sync  ┌──────────┐                  │ │
│  │ │  Node A  │←─────→│  Node B  │                  │ │
│  │ │(Primary) │       │(Secondary)│                  │ │
│  │ └────┬─────┘       └──────────┘                  │ │
│  │      │                                             │ │
│  │      │ Async (Protocol A)                         │ │
│  │      ↓                                             │ │
│  │ ┌─────────────────────────────────────────────┐  │ │
│  │ │         WAN / Internet                      │  │ │
│  │ └─────────────────────────────────────────────┘  │ │
│  │      ↓                                             │ │
│  │ DR Site                                            │ │
│  │ ┌──────────┐                                      │ │
│  │ │  Node C  │                                      │ │
│  │ │(Secondary)│                                      │ │
│  │ └──────────┘                                      │ │
│  │                                                     │ │
│  │ Benefits:                                          │ │
│  │ - Zero data loss locally (Protocol C)              │ │
│  │ - Remote backup for disaster recovery              │ │
│  │ - Kernel TX Buffering for long distance            │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

## 9. 모니터링 및 디버깅

### 9.1 디버깅 인터페이스

```
┌──────────────────────────────────────────────────────────┐
│              Debugging and Monitoring                     │
│                                                           │
│  Linux DebugFS:                                           │
│  ┌────────────────────────────────────────────────────┐ │
│  │ /sys/kernel/debug/bsr/                             │ │
│  │   ├── resources/                                   │ │
│  │   │   ├── resource_name/                           │ │
│  │   │   │   ├── connections/                         │ │
│  │   │   │   │   └── peer_name/                       │ │
│  │   │   │   │       ├── in_flight_summary            │ │
│  │   │   │   │       └── data_gen_id                  │ │
│  │   │   │   ├── volumes/                             │ │
│  │   │   │   │   └── volume_number/                   │ │
│  │   │   │   │       ├── resync_extents               │ │
│  │   │   │   │       └── act_log_extents              │ │
│  │   │   │   └── in_flight_summary                    │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Status Commands:                                         │
│  ┌────────────────────────────────────────────────────┐ │
│  │ bsradm status                                      │ │
│  │ bsradm status --verbose                            │ │
│  │ bsradm status --statistics                         │ │
│  │ bsrsetup status resource_name                      │ │
│  └────────────────────────────────────────────────────┘ │
│                                                           │
│  Logging:                                                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │ Kernel Log (dmesg, /var/log/kern.log)              │ │
│  │ BSR-specific log levels                            │ │
│  │ Configurable verbosity                             │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

---

**문서 버전**: 1.0
**작성일**: 2025-10-30
**작성자**: GitHub Copilot Agent
