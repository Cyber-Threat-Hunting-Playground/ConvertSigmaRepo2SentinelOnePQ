```sql
// Translated content (automatically translated on 03-10-2026 02:47:52):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\opale-agent.exe" or tgt.process.image.path contains "\\opale-agent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Opale RMM Tool Process Activity
id: 27dcde5f-cae1-59a9-aef0-c933230e9878
status: experimental
description: |
    Detects potential processes activity of Opale RMM tool
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
        ParentImage|endswith: '\\opale-agent.exe'
    selection_image:
        Image|endswith: '\\opale-agent.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Opale
level: medium
```
