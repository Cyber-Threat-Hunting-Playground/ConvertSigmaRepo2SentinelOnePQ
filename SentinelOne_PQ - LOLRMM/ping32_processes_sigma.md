```sql
// Translated content (automatically translated on 28-10-2026 02:56:19):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\NSecRTS.exe" or tgt.process.image.path contains "\\NSecRTS.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Ping32 RMM Tool Process Activity
id: bf9700b5-9230-5ed8-88e4-124183e0e413
status: experimental
description: |
    Detects potential processes activity of Ping32 RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-19
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\\NSecRTS.exe'
    selection_image:
        Image|endswith: '\\NSecRTS.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Ping32
level: medium
```
