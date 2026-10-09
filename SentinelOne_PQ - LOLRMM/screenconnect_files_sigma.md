```sql
// Translated content (automatically translated on 09-10-2026 03:32:42):
event.category="file" and (endpoint.os="windows" and (tgt.file.path="*C:\\Program Files*\\ScreenConnect\\App_Data\\Session.db" or tgt.file.path="*C:\\Program Files*\\ScreenConnect\\App_Data\\User.xml" or tgt.file.path="*C:\\ProgramData\\ScreenConnect Client*\\user.config" or tgt.file.path="*C:\\Program Files (x86)\\ScreenConnect Client (*)\\system.config" or tgt.file.path="*C:\\Program Files*\\ScreenConnect Client*\\app.config" or tgt.file.path contains "C:\\Windows\\SystemTemp\\ScreenConnect\*"))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenConnect RMM Tool File Activity
id: fa0f2b6a-8f96-470e-b699-82e4c1bce912
status: experimental
description: |
    Detects potential files activity of ScreenConnect RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files*\ScreenConnect\App_Data\Session.db'
            - 'C:\Program Files*\ScreenConnect\App_Data\User.xml'
            - 'C:\ProgramData\ScreenConnect Client*\user.config'
            - 'C:\Program Files (x86)\ScreenConnect Client (*)\system.config'
            - 'C:\Program Files*\ScreenConnect Client*\app.config'
            - 'C:\Windows\SystemTemp\ScreenConnect\*'
    condition: selection
falsepositives:
    - Legitimate use of ScreenConnect
level: medium
```
