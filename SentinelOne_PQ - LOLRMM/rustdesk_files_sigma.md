```sql
// Translated content (automatically translated on 08-10-2026 03:27:06):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\RustDesk\*" or tgt.file.path contains "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\RustDesk\\config\\RustDesk2.toml" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RustDesk\\config\\RustDesk.toml" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RustDesk\\config\\RustDesk2.toml" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\RustDesk\\log\*" or tgt.file.path contains "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\RustDesk Tray.lnk"))
```


# Original Sigma Rule:
```yaml
title: Potential RustDesk RMM Tool File Activity
id: 08f48f25-fcee-48af-b7c3-8d8d128c7f64
status: experimental
description: |
    Detects potential files activity of RustDesk RMM tool
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
            - 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\*'
            - 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml'
            - 'C:\Users\*\AppData\Roaming\RustDesk\config\RustDesk.toml'
            - 'C:\Users\*\AppData\Roaming\RustDesk\config\RustDesk2.toml'
            - 'C:\Users\*\AppData\Roaming\RustDesk\log\*'
            - 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\RustDesk Tray.lnk'
    condition: selection
falsepositives:
    - Legitimate use of RustDesk
level: medium
```
