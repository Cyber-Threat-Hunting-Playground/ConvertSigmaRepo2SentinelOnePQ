```sql
// Translated content (automatically translated on 06-10-2026 03:43:55):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\ProgramData\\Opale\\opale-agent.exe" or tgt.file.path contains "C:\\ProgramData\\Opale\\config.json" or tgt.file.path contains "C:\\ProgramData\\Opale\\state.json" or tgt.file.path contains "C:\\ProgramData\\Opale\\agent.log"))
```


# Original Sigma Rule:
```yaml
title: Potential Opale RMM Tool File Activity
id: d057c1f9-6a34-5e09-899f-b8598b74ffe4
status: experimental
description: |
    Detects potential files activity of Opale RMM tool
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
            - 'C:\ProgramData\Opale\opale-agent.exe'
            - 'C:\ProgramData\Opale\config.json'
            - 'C:\ProgramData\Opale\state.json'
            - 'C:\ProgramData\Opale\agent.log'
    condition: selection
falsepositives:
    - Legitimate use of Opale
level: medium
```
