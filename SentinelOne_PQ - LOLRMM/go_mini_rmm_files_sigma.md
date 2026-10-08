```sql
// Translated content (automatically translated on 08-10-2026 03:27:06):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\rmm\\agent.exe" or tgt.file.path contains "C:\\rmm\\config.json"))
```


# Original Sigma Rule:
```yaml
title: Potential Go Mini RMM RMM Tool File Activity
id: a78d0771-bf4a-5a73-a0dd-c6f1f3847d12
status: experimental
description: |
    Detects potential files activity of Go Mini RMM RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-29
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\rmm\agent.exe'
            - 'C:\rmm\config.json'
    condition: selection
falsepositives:
    - Legitimate use of Go Mini RMM
level: medium
```
