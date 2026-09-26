```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\RemoteAgent\\RemoteAgentAgent.exe" or tgt.file.path contains "C:\\Program Files\\RemoteAgent\\config.json" or tgt.file.path contains "C:\\Windows\\Temp\\RemoteAgent.msi"))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteAgentAgent RMM Tool File Activity
id: e23f97c0-5469-53f4-b3c3-0e8107d64c28
status: experimental
description: |
    Detects potential files activity of RemoteAgentAgent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files\RemoteAgent\RemoteAgentAgent.exe'
            - 'C:\Program Files\RemoteAgent\config.json'
            - 'C:\Windows\Temp\RemoteAgent.msi'
    condition: selection
falsepositives:
    - Legitimate use of RemoteAgentAgent
level: medium
```
