```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\OpenDesk-RMM-Agent.exe" or tgt.process.image.path contains "\\OpenDesk-RMM-Agent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential OpenDesk RMM Agent RMM Tool Process Activity
id: c4ca8292-f8c2-58f8-9d47-573a57e50919
status: experimental
description: |
    Detects potential processes activity of OpenDesk RMM Agent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\\OpenDesk-RMM-Agent.exe'
    selection_image:
        Image|endswith: '\\OpenDesk-RMM-Agent.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of OpenDesk RMM Agent
level: medium
```
