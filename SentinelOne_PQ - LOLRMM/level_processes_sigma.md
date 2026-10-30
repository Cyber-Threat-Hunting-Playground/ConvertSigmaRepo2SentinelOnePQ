```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\level-windows-amd64.exe" or src.process.image.path contains "\\level.exe" or src.process.image.path contains "\\level-remote-control-ffmpeg.exe") or (tgt.process.image.path contains "\\level-windows-amd64.exe" or tgt.process.image.path contains "\\level.exe" or tgt.process.image.path contains "\\level-remote-control-ffmpeg.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Level RMM Tool Process Activity
id: cf98e4dc-1ad9-5221-8037-a794f3d48ee1
status: experimental
description: |
    Detects potential processes activity of Level RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-28
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\level-windows-amd64.exe'
            - '\\level.exe'
            - '\\level-remote-control-ffmpeg.exe'
    selection_image:
        Image|endswith:
            - '\\level-windows-amd64.exe'
            - '\\level.exe'
            - '\\level-remote-control-ffmpeg.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Level
level: medium
```
