```sql
// Translated content (automatically translated on 07-10-2026 03:11:23):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "C:\\Program Files (x86)\\N-able Technologies\\Windows Agent\\bin\\agent.exe" or src.process.image.path contains "\\AgentMaint.exe" or src.process.image.path contains "\\AgentMonitor.exe" or src.process.image.path contains "\\BASupTSHelper.exe" or src.process.image.path contains "\\msp-agent-core.exe") or (tgt.process.image.path contains "C:\\Program Files (x86)\\N-able Technologies\\Windows Agent\\bin\\agent.exe" or tgt.process.image.path contains "\\AgentMaint.exe" or tgt.process.image.path contains "\\AgentMonitor.exe" or tgt.process.image.path contains "\\BASupTSHelper.exe" or tgt.process.image.path contains "\\msp-agent-core.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential N-able N-central RMM Tool Process Activity
id: 0ca0f2f0-d7bc-5987-ace9-830993caae1a
status: experimental
description: |
    Detects potential processes activity of N-able N-central RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-05
modified: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - 'C:\\Program Files (x86)\\N-able Technologies\\Windows Agent\\bin\\agent.exe'
            - '\\AgentMaint.exe'
            - '\\AgentMonitor.exe'
            - '\\BASupTSHelper.exe'
            - '\\msp-agent-core.exe'
    selection_image:
        Image|endswith:
            - 'C:\\Program Files (x86)\\N-able Technologies\\Windows Agent\\bin\\agent.exe'
            - '\\AgentMaint.exe'
            - '\\AgentMonitor.exe'
            - '\\BASupTSHelper.exe'
            - '\\msp-agent-core.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of N-able N-central
level: medium
```
