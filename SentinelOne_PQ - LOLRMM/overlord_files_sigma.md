```sql
// Translated content (automatically translated on 10-10-2026 03:12:59):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\Microsoft\\DeviceSync\\svchost.exe" or tgt.file.path="*C:\\Users\*\\AppData\\Roaming\\Microsoft\\DeviceSync\\ovd_*.exe" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.exe" or tgt.file.path="*C:\\Users\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ovd_*.exe" or tgt.file.path="*C:\\Users\*\\AppData\\Local\\Temp\\svchost-windows-amd64-*.exe" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\Overlord\\agent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Overlord RMM Tool File Activity
id: f07c63ec-73ba-5af5-b119-4c604702593e
status: experimental
description: |
    Detects potential files activity of Overlord RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Users\*\AppData\Roaming\Microsoft\DeviceSync\svchost.exe'
            - 'C:\Users\*\AppData\Roaming\Microsoft\DeviceSync\ovd_*.exe'
            - 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\svchost.exe'
            - 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ovd_*.exe'
            - 'C:\Users\*\AppData\Local\Temp\svchost-windows-amd64-*.exe'
            - 'C:\Users\*\AppData\Roaming\Overlord\agent.exe'
    condition: selection
falsepositives:
    - Legitimate use of Overlord
level: medium
```
