﻿﻿# BSR
                           
## Synopsis
Block Sync & Replication (BSR) is an open source project that implements software-based block replication over the network. It is based on a kernel-level replication engine and supports Windows and Linux cross-platform environments. BSR originally started out as a WDRBD project and only supported the Windows environment, but now extends to the Linux environment to support cross-platforms.

## Motivation
We have ported the source code of Linux DRBD 9.0 to Windows via WDRBD and have done it successfully. At present, WDRBD has already been widely deployed and used in enterprise HA environments for years, proving its performance and reliability. But in the process, we had to endure too much pain. The original DRBD9 suffered from all sorts of bugs, including unclear synchronization logic, OOS remaining problems, and synchronization interruptions due to instability of 1:N replication and hasn't solved these problems for years. Based on the DRBD9 engine, we had to analyze the DRBD engine itself, fix it to our taste, and fix various bugs ourselves.

It was not easy to solve these problems, but we finally achieved stabilization of WDRBD, and now we want to extend it to the Linux environment through the BSR project.

BSR will become a block replication cross-platform open source project supporting Windows and Linux based on the BSR engine.

## Contributors
Man Technology Inc.(http://www.mantech.co.kr/)

## License
This project is licensed under the GPL v2
