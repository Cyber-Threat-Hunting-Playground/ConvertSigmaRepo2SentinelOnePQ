```sql
// Translated content (automatically translated on 03-10-2026 02:47:52):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\obliance-agent.exe" or src.process.image.path contains "\\obliance-tray.exe" or src.process.image.path contains "\\obliance-watchdog.exe") or (tgt.process.image.path contains "\\obliance-agent.exe" or tgt.process.image.path contains "\\obliance-tray.exe" or tgt.process.image.path contains "\\obliance-watchdog.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Obliance RMM Tool Process Activity
id: 70bff6da-1cc5-5361-ae30-e4ae692b07e4
status: experimental
description: |
    Detects potential processes activity of Obliance RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-29
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\obliance-agent.exe'
            - '\\obliance-tray.exe'
            - '\\obliance-watchdog.exe'
    selection_image:
        Image|endswith:
            - '\\obliance-agent.exe'
            - '\\obliance-tray.exe'
            - '\\obliance-watchdog.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Obliance
level: medium
```
