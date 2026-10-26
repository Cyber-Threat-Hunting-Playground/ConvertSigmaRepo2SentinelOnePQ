```sql
// Translated content (automatically translated on 26-10-2026 02:11:30):
event.category="file" and (endpoint.os="windows" and tgt.file.path contains "C:\\Windows\\debug\\code-insiders.exe")
```


# Original Sigma Rule:
```yaml
title: Potential VS Code Remote Tunnels RMM Tool File Activity
id: 0f26737a-9b0f-5f03-a0ef-62789938533d
status: experimental
description: |
    Detects potential files activity of VS Code Remote Tunnels RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-20
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'C:\Windows\debug\code-insiders.exe'
    condition: selection
falsepositives:
    - Legitimate use of VS Code Remote Tunnels
level: medium
```
