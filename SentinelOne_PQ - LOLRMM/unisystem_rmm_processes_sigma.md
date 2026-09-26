```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\UniRMM.exe" or tgt.process.image.path contains "\\UniRMM.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential UniSystem RMM RMM Tool Process Activity
id: 37c2dee5-a340-53b6-9931-b7cde1a58fcc
status: experimental
description: |
    Detects potential processes activity of UniSystem RMM RMM tool
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
        ParentImage|endswith: '\\UniRMM.exe'
    selection_image:
        Image|endswith: '\\UniRMM.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of UniSystem RMM
level: medium
```
