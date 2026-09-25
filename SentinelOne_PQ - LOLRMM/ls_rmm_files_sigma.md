```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\LS RMM\\LS RMM.exe" or tgt.file.path contains "\\LS RMM\\LS RMM Worker.exe" or tgt.file.path contains "\\LS RMM\\LS RMM-Update.exe" or tgt.file.path contains "\\LS RMM\\LSRMMupdate.txt" or tgt.file.path contains "\\LS RMM\\SC.exe" or tgt.file.path contains "\\LS RMM\\SC.bmp"))
```


# Original Sigma Rule:
```yaml
title: Potential LS RMM RMM Tool File Activity
id: ab9ac323-db59-50a6-84fa-a41e60890904
status: experimental
description: |
    Detects potential files activity of LS RMM RMM tool
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
            - '*\LS RMM\LS RMM.exe'
            - '*\LS RMM\LS RMM Worker.exe'
            - '*\LS RMM\LS RMM-Update.exe'
            - '*\LS RMM\LSRMMupdate.txt'
            - '*\LS RMM\SC.exe'
            - '*\LS RMM\SC.bmp'
    condition: selection
falsepositives:
    - Legitimate use of LS RMM
level: medium
```
