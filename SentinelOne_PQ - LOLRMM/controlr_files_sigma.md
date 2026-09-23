```sql
// Translated content (automatically translated on 23-09-2026 02:18:07):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\ControlR.Agent.Installer.exe" or tgt.file.path contains "C:\\Program Files\\ControlR\*\\ControlR.Agent.exe" or tgt.file.path contains "C:\\ProgramData\\ControlR\*\\appsettings.json" or tgt.file.path="*C:\\ProgramData\\ControlR\*\\Logs\\ControlR.Agent\\LogFile*.log" or tgt.file.path="*C:\\ProgramData\\ControlR\*\\Logs\\ControlR.DesktopClient\\LogFile*.log"))
```


# Original Sigma Rule:
```yaml
title: Potential ControlR RMM Tool File Activity
id: b2e670c3-2d33-5772-9fc4-1252ee6126ae
status: experimental
description: |
    Detects potential files activity of ControlR RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-08-18
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
            - '*\ControlR.Agent.Installer.exe'
            - 'C:\Program Files\ControlR\*\ControlR.Agent.exe'
            - 'C:\ProgramData\ControlR\*\appsettings.json'
            - 'C:\ProgramData\ControlR\*\Logs\ControlR.Agent\LogFile*.log'
            - 'C:\ProgramData\ControlR\*\Logs\ControlR.DesktopClient\LogFile*.log'
    condition: selection
falsepositives:
    - Legitimate use of ControlR
level: medium
```
