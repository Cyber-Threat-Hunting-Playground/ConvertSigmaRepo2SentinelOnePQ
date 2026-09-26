```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\nexusrmm.exe" or tgt.process.image.path contains "\\nexusrmm.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Nexus RMM (Scogo) RMM Tool Process Activity
id: 21a900de-d6f8-5aa3-8839-117b06ffa7bc
status: experimental
description: |
    Detects potential processes activity of Nexus RMM (Scogo) RMM tool
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
        ParentImage|endswith: '\\nexusrmm.exe'
    selection_image:
        Image|endswith: '\\nexusrmm.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Nexus RMM (Scogo)
level: medium
```
