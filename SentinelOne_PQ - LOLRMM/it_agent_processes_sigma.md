```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\ITAgentRMMSender.exe" or src.process.image.path contains "\\ITAgentRMMSenderSL.exe" or src.process.image.path contains "\\ITAgentRMMSenderUpdater.exe") or (tgt.process.image.path contains "\\ITAgentRMMSender.exe" or tgt.process.image.path contains "\\ITAgentRMMSenderSL.exe" or tgt.process.image.path contains "\\ITAgentRMMSenderUpdater.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential IT Agent RMM Tool Process Activity
id: 0f5550be-9212-569e-a07b-bf652e3d0759
status: experimental
description: |
    Detects potential processes activity of IT Agent RMM tool
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
        ParentImage|endswith:
            - '\\ITAgentRMMSender.exe'
            - '\\ITAgentRMMSenderSL.exe'
            - '\\ITAgentRMMSenderUpdater.exe'
    selection_image:
        Image|endswith:
            - '\\ITAgentRMMSender.exe'
            - '\\ITAgentRMMSenderSL.exe'
            - '\\ITAgentRMMSenderUpdater.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of IT Agent
level: medium
```
