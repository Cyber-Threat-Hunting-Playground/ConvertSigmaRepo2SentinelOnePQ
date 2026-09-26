```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\AppData\\Roaming\\rmm.exe" or tgt.file.path contains "C:\\ProgramData\\RMMAgent\\client_id.bin" or tgt.file.path contains "C:\\ProgramData\\RMMAgent\\credentials.dat" or tgt.file.path contains "C:\\ProgramData\\RMMAgent\\packages\\Notepad++.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RMMCRAT RMM Tool File Activity
id: 9f2962ec-eff6-59a9-b66f-4141705d3b51
status: experimental
description: |
    Detects potential files activity of RMMCRAT RMM tool
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
            - '*\AppData\Roaming\rmm.exe'
            - 'C:\ProgramData\RMMAgent\client_id.bin'
            - 'C:\ProgramData\RMMAgent\credentials.dat'
            - 'C:\ProgramData\RMMAgent\packages\Notepad++.exe'
    condition: selection
falsepositives:
    - Legitimate use of RMMCRAT
level: medium
```
