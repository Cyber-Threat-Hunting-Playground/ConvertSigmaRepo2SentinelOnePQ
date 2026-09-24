```sql
// Translated content (automatically translated on 24-09-2026 02:05:20):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\MiniRmmAgent.exe" or tgt.process.image.path contains "\\MiniRmmAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Mini RMM Agent RMM Tool Process Activity
id: de9aa238-4ece-5cd8-b47a-78d5c1653bc7
status: experimental
description: |
    Detects potential processes activity of Mini RMM Agent RMM tool
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
        ParentImage|endswith: '\\MiniRmmAgent.exe'
    selection_image:
        Image|endswith: '\\MiniRmmAgent.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Mini RMM Agent
level: medium
```
