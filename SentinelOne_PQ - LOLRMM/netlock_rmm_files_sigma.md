```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\temp\\netlock rmm\\installer\\logs\*" or tgt.file.path contains "C:\\ProgramData\\0x101 Cyber Security\\NetLock RMM\\Comm Agent\\server_config.json"))
```


# Original Sigma Rule:
```yaml
title: Potential NetLock RMM RMM Tool File Activity
id: 60d10413-e93a-4f1a-b1cc-eb5d0cb861ca
status: experimental
description: |
    Detects potential files activity of NetLock RMM RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-22
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\temp\netlock rmm\installer\logs\*'
            - 'C:\ProgramData\0x101 Cyber Security\NetLock RMM\Comm Agent\server_config.json'
    condition: selection
falsepositives:
    - Legitimate use of NetLock RMM
level: medium
```
