```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\Lavawall\\LavawallWin.exe" or tgt.file.path contains "\\Lavawall\\remote-agent\\remote-agent.exe" or tgt.file.path contains "\\Lavawall\\remote-agent\\uihelper.exe" or tgt.file.path contains "\\Lavawall\\LavawallCheckAndStartService.ps1" or tgt.file.path contains "\\Lavawall\\Storage\\UserAgentData.db" or tgt.file.path contains "\\LavawallWin.dll" or tgt.file.path contains "\\LavawallWin.runtimeconfig.json"))
```


# Original Sigma Rule:
```yaml
title: Potential Lavawall RMM Tool File Activity
id: 5d9eca27-9134-565b-bcdf-c78796e84f0c
status: experimental
description: |
    Detects potential files activity of Lavawall RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-22
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '*\Lavawall\LavawallWin.exe'
            - '*\Lavawall\remote-agent\remote-agent.exe'
            - '*\Lavawall\remote-agent\uihelper.exe'
            - '*\Lavawall\LavawallCheckAndStartService.ps1'
            - '*\Lavawall\Storage\UserAgentData.db'
            - '*\LavawallWin.dll'
            - '*\LavawallWin.runtimeconfig.json'
    condition: selection
falsepositives:
    - Legitimate use of Lavawall
level: medium
```
