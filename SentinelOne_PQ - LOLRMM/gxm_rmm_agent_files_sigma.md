```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\ProgramData\\GxM\\agent\\GxM.Agent.exe" or tgt.file.path contains "\\ProgramData\\GxM\\enrollment.json" or tgt.file.path contains "\\ProgramData\\GxM\\install.log"))
```


# Original Sigma Rule:
```yaml
title: Potential GxM RMM Agent RMM Tool File Activity
id: fe752b7e-ffef-5fac-85a0-387659f544cd
status: experimental
description: |
    Detects potential files activity of GxM RMM Agent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '*\ProgramData\GxM\agent\GxM.Agent.exe'
            - '*\ProgramData\GxM\enrollment.json'
            - '*\ProgramData\GxM\install.log'
    condition: selection
falsepositives:
    - Legitimate use of GxM RMM Agent
level: medium
```
