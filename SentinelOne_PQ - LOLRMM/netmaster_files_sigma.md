```sql
// Translated content (automatically translated on 09-10-2026 03:32:42):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\ProgramData\\NetMaster\\NetMaster_Client.exe" or tgt.file.path contains "C:\\ProgramData\\NetMaster\\config.ini" or tgt.file.path contains "C:\\ProgramData\\NetMaster\\log.txt"))
```


# Original Sigma Rule:
```yaml
title: Potential NetMaster RMM Tool File Activity
id: e39b474d-bfdd-5db8-9d34-42bcff1140de
status: experimental
description: |
    Detects potential files activity of NetMaster RMM tool
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
            - 'C:\ProgramData\NetMaster\NetMaster_Client.exe'
            - 'C:\ProgramData\NetMaster\config.ini'
            - 'C:\ProgramData\NetMaster\log.txt'
    condition: selection
falsepositives:
    - Legitimate use of NetMaster
level: medium
```
