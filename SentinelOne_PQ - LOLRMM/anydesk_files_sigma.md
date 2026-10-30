```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\AppData\\Roaming\\AnyDesk\\file_transfer_trace.txt" or tgt.file.path contains "\\ProgramData\\AnyDesk\\file_transfer_trace.txt" or tgt.file.path="*\\ProgramData\\AnyDesk\\ad_*\\ad_*_svc.trace" or tgt.file.path="*\\AppData\\Roaming\\AnyDesk\\ad_*\\ad_*.trace" or tgt.file.path="*\\AppData\\Roaming\\AnyDesk\\ad_*\\chat\*.txt" or tgt.file.path="*\\AppData\\Roaming\\AnyDesk\\ad_*\\user.conf" or tgt.file.path="*\\AppData\\Roaming\\AnyDesk\\ad_*\\service.conf" or tgt.file.path="*\\ProgramData\\AnyDesk\\ad_*\\service.conf" or tgt.file.path="*\\ProgramData\\AnyDesk\\ad_*\\system.conf" or tgt.file.path="*\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\AnyDesk *.lnk" or tgt.file.path contains "C:\\Users\*\\Videos\\AnyDesk\*.anydesk" or tgt.file.path contains "C:\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\Roaming\\AnyDesk\*"))
```


# Original Sigma Rule:
```yaml
title: Potential AnyDesk RMM Tool File Activity
id: 57cb129e-6cd6-42e9-8b5d-04542121fd79
status: experimental
description: |
    Detects potential files activity of AnyDesk RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-10-28
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '*\AppData\Roaming\AnyDesk\file_transfer_trace.txt'
            - '*\ProgramData\AnyDesk\file_transfer_trace.txt'
            - '*\ProgramData\AnyDesk\ad_*\ad_*_svc.trace'
            - '*\AppData\Roaming\AnyDesk\ad_*\ad_*.trace'
            - '*\AppData\Roaming\AnyDesk\ad_*\chat\*.txt'
            - '*\AppData\Roaming\AnyDesk\ad_*\user.conf'
            - '*\AppData\Roaming\AnyDesk\ad_*\service.conf'
            - '*\ProgramData\AnyDesk\ad_*\service.conf'
            - '*\ProgramData\AnyDesk\ad_*\system.conf'
            - '*\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\AnyDesk *.lnk'
            - 'C:\Users\*\Videos\AnyDesk\*.anydesk'
            - 'C:\Windows\SysWOW64\config\systemprofile\AppData\Roaming\AnyDesk\*'
    condition: selection
falsepositives:
    - Legitimate use of AnyDesk
level: medium
```
