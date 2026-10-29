```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "TeamViewer\\d\\d_Logfile\\.log" or tgt.file.path contains "C:\\Program Files\\TeamViewer\\Connections_incoming.txt" or tgt.file.path contains "C:\\Program Files\\TeamViewer\\TVNetwork.log" or tgt.file.path contains "teamviewerqs.exe" or tgt.file.path contains "tv_w32.exe" or tgt.file.path contains "tv_w64.exe" or tgt.file.path contains "tv_x64.exe" or tgt.file.path contains "teamviewer.exe" or tgt.file.path contains "teamviewer_service.exe" or tgt.file.path="*C:\\Program Files*\\TeamViewer\\connections*.txt" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\TeamViewer\\MRU\\RemoteSupport\*tvc"))
```


# Original Sigma Rule:
```yaml
title: Potential TeamViewer RMM Tool File Activity
id: fe921b8e-7f8f-4e35-a91e-a4579aa4fd09
status: experimental
description: |
    Detects potential files activity of TeamViewer RMM tool
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
            - 'TeamViewer\d\d_Logfile\.log'
            - 'C:\Program Files\TeamViewer\Connections_incoming.txt'
            - 'C:\Program Files\TeamViewer\TVNetwork.log'
            - 'teamviewerqs.exe'
            - 'tv_w32.exe'
            - 'tv_w64.exe'
            - 'tv_x64.exe'
            - 'teamviewer.exe'
            - 'teamviewer_service.exe'
            - 'C:\Program Files*\TeamViewer\connections*.txt'
            - 'C:\Users\*\AppData\Roaming\TeamViewer\MRU\RemoteSupport\*tvc'
    condition: selection
falsepositives:
    - Legitimate use of TeamViewer
level: medium
```
