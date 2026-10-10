```sql
// Translated content (automatically translated on 10-10-2026 03:12:59):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\topiad.exe" or tgt.process.image.path contains "\\topiad.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Vicarius vRx RMM Tool Process Activity
id: 2be9e8d9-9505-5882-8992-f6ec16fcbb03
status: experimental
description: |
    Detects potential processes activity of Vicarius vRx RMM tool
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
        ParentImage|endswith: '\\topiad.exe'
    selection_image:
        Image|endswith: '\\topiad.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Vicarius vRx
level: medium
```
