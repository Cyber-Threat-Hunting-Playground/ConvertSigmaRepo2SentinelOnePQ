```sql
// Translated content (automatically translated on 23-09-2026 02:18:07):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\ZecuritAgentService.exe" or src.process.image.path contains "\\ZecuritAgentRegister.exe" or src.process.image.path contains "\\ZecuritAgentTray.exe" or src.process.image.path contains "\\ZecuritAgentAssetMgr.exe" or src.process.image.path contains "\\ZecuritLiveNotifier.exe" or src.process.image.path contains "\\ZecuritCommandProcessor.exe" or src.process.image.path contains "\\ZecuritRemoteTools.exe" or src.process.image.path contains "\\ZecuritScreenReaderService.exe" or src.process.image.path contains "\\ZecuritScreenReaderApp.exe" or src.process.image.path contains "\\ZecuritScreenReaderAppUI.exe" or src.process.image.path contains "\\ZecuritApplicationControlService.exe" or src.process.image.path contains "\\ZecuritAgentUpgrader.exe") or (tgt.process.image.path contains "\\ZecuritAgentService.exe" or tgt.process.image.path contains "\\ZecuritAgentRegister.exe" or tgt.process.image.path contains "\\ZecuritAgentTray.exe" or tgt.process.image.path contains "\\ZecuritAgentAssetMgr.exe" or tgt.process.image.path contains "\\ZecuritLiveNotifier.exe" or tgt.process.image.path contains "\\ZecuritCommandProcessor.exe" or tgt.process.image.path contains "\\ZecuritRemoteTools.exe" or tgt.process.image.path contains "\\ZecuritScreenReaderService.exe" or tgt.process.image.path contains "\\ZecuritScreenReaderApp.exe" or tgt.process.image.path contains "\\ZecuritScreenReaderAppUI.exe" or tgt.process.image.path contains "\\ZecuritApplicationControlService.exe" or tgt.process.image.path contains "\\ZecuritAgentUpgrader.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Zecurit RMM Tool Process Activity
id: 039daedd-9928-586a-b884-d23a2a484d1d
status: experimental
description: |
    Detects potential processes activity of Zecurit RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-22
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\ZecuritAgentService.exe'
            - '\\ZecuritAgentRegister.exe'
            - '\\ZecuritAgentTray.exe'
            - '\\ZecuritAgentAssetMgr.exe'
            - '\\ZecuritLiveNotifier.exe'
            - '\\ZecuritCommandProcessor.exe'
            - '\\ZecuritRemoteTools.exe'
            - '\\ZecuritScreenReaderService.exe'
            - '\\ZecuritScreenReaderApp.exe'
            - '\\ZecuritScreenReaderAppUI.exe'
            - '\\ZecuritApplicationControlService.exe'
            - '\\ZecuritAgentUpgrader.exe'
    selection_image:
        Image|endswith:
            - '\\ZecuritAgentService.exe'
            - '\\ZecuritAgentRegister.exe'
            - '\\ZecuritAgentTray.exe'
            - '\\ZecuritAgentAssetMgr.exe'
            - '\\ZecuritLiveNotifier.exe'
            - '\\ZecuritCommandProcessor.exe'
            - '\\ZecuritRemoteTools.exe'
            - '\\ZecuritScreenReaderService.exe'
            - '\\ZecuritScreenReaderApp.exe'
            - '\\ZecuritScreenReaderAppUI.exe'
            - '\\ZecuritApplicationControlService.exe'
            - '\\ZecuritAgentUpgrader.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Zecurit
level: medium
```
