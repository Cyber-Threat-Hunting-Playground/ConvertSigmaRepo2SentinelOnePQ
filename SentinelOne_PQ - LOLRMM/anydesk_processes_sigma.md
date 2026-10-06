```sql
// Translated content (automatically translated on 06-10-2026 03:43:55):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\AnyDesk.exe" or src.process.image.path="*\\AnyDesk-*.exe") or (tgt.process.image.path contains "\\AnyDesk.exe" or tgt.process.image.path="*\\AnyDesk-*.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential AnyDesk RMM Tool Process Activity
id: 3f394576-7f89-586c-bba6-26d639a6e4ee
status: experimental
description: |
    Detects potential processes activity of AnyDesk RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\AnyDesk.exe'
            - '\\AnyDesk-*.exe'
    selection_image:
        Image|endswith:
            - '\\AnyDesk.exe'
            - '\\AnyDesk-*.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of AnyDesk
level: medium
```
