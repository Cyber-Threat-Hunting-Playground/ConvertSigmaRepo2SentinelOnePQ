```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\rdviewer\\rdclient\*" or tgt.file.path contains "\\rdpro\\RdClient.exe" or tgt.file.path contains "\\rdpro\\rdService.exe" or tgt.file.path contains "\\rdpro\\rdlibw.dll" or tgt.file.path contains "\\rdpro\\cfg.ini" or tgt.file.path contains "\\rdpro\\host.dat" or tgt.file.path contains "C:\\ProgramData\\host\\dmservice.exe" or tgt.file.path contains "C:\\ProgramData\\host\\diskmgr.exe" or tgt.file.path contains "C:\\ProgramData\\host\\cfg.ini" or tgt.file.path contains "C:\\ProgramData\\host\\host.dat" or tgt.file.path contains "\\RdViewerPro\\RdServer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RdViewer RMM Tool File Activity
id: cc3fb8a1-6946-5d8b-8c59-41224c68b066
status: experimental
description: |
    Detects potential files activity of RdViewer RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-28
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files (x86)\rdviewer\rdclient\*'
            - '*\rdpro\RdClient.exe'
            - '*\rdpro\rdService.exe'
            - '*\rdpro\rdlibw.dll'
            - '*\rdpro\cfg.ini'
            - '*\rdpro\host.dat'
            - 'C:\ProgramData\host\dmservice.exe'
            - 'C:\ProgramData\host\diskmgr.exe'
            - 'C:\ProgramData\host\cfg.ini'
            - 'C:\ProgramData\host\host.dat'
            - '*\RdViewerPro\RdServer.exe'
    condition: selection
falsepositives:
    - Legitimate use of RdViewer
level: medium
```
