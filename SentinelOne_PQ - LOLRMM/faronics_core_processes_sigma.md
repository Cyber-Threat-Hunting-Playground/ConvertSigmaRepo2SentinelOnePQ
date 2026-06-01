```sql
// Translated content (automatically translated on 01-06-2026 02:36:33):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "FaronicsCoreAgent.exe" or src.process.image.path contains "CoreAgentService.exe" or src.process.image.path contains "FaronicsCoreAgent.exe" or src.process.image.path contains "CoreAgentService.exe") or (tgt.process.image.path contains "FaronicsCoreAgent.exe" or tgt.process.image.path contains "CoreAgentService.exe" or tgt.process.image.path contains "FaronicsCoreAgent.exe" or tgt.process.image.path contains "CoreAgentService.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Core RMM Tool Process Activity
id: 93f310da-02e3-5710-9cbc-23113673d182
status: experimental
description: |
    Detects potential processes activity of Faronics Core RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - 'FaronicsCoreAgent.exe'
            - 'CoreAgentService.exe'
            - 'FaronicsCoreAgent.exe'
            - 'CoreAgentService.exe'
    selection_image:
        Image|endswith:
            - 'FaronicsCoreAgent.exe'
            - 'CoreAgentService.exe'
            - 'FaronicsCoreAgent.exe'
            - 'CoreAgentService.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Faronics Core
level: medium
```
