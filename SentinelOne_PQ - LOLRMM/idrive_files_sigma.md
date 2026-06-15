```sql
// Translated content (automatically translated on 15-06-2026 02:39:25):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\ProgramData\\IDrive\*" or tgt.file.path contains "C:\\Program Files\\IDrive\*" or tgt.file.path contains "C:\\Program Files (x86)\\IDrive\*" or tgt.file.path contains "C:\\Users\*\\AppData\\Local\\IDrive\*"))
```


# Original Sigma Rule:
```yaml
title: Potential iDrive RMM Tool File Activity
id: 6b92f296-e412-5864-806f-02120af6615f
status: experimental
description: |
    Detects potential files activity of iDrive RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\ProgramData\IDrive\*'
            - 'C:\Program Files\IDrive\*'
            - 'C:\Program Files (x86)\IDrive\*'
            - 'C:\Users\*\AppData\Local\IDrive\*'
    condition: selection
falsepositives:
    - Legitimate use of iDrive
level: medium
```
