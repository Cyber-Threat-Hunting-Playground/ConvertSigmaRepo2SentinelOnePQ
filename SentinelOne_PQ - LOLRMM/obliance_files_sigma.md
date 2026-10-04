```sql
// Translated content (automatically translated on 04-10-2026 03:17:47):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\OblianceAgent\\obliance-agent.exe" or tgt.file.path contains "C:\\Program Files\\OblianceAgent\\obliance-tray.exe" or tgt.file.path contains "C:\\Program Files\\OblianceAgent\\obliance-watchdog.exe" or tgt.file.path contains "C:\\ProgramData\\OblianceAgent\\config.json" or tgt.file.path contains "C:\\ProgramData\\OblianceAgent\\agent.log" or tgt.file.path contains "C:\\ProgramData\\OblianceAgent\\watchdog.json"))
```


# Original Sigma Rule:
```yaml
title: Potential Obliance RMM Tool File Activity
id: bff733ac-d0ce-57db-9722-34ea1af6e7b5
status: experimental
description: |
    Detects potential files activity of Obliance RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-29
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files\OblianceAgent\obliance-agent.exe'
            - 'C:\Program Files\OblianceAgent\obliance-tray.exe'
            - 'C:\Program Files\OblianceAgent\obliance-watchdog.exe'
            - 'C:\ProgramData\OblianceAgent\config.json'
            - 'C:\ProgramData\OblianceAgent\agent.log'
            - 'C:\ProgramData\OblianceAgent\watchdog.json'
    condition: selection
falsepositives:
    - Legitimate use of Obliance
level: medium
```
