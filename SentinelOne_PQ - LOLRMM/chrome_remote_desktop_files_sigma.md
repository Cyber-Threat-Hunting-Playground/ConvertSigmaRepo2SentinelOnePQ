```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.category="file" and (endpoint.os="windows" and tgt.file.path contains "C:\\Program Files (x86)\\Google\\Chrome Remote Desktop\*\\remoting_host.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Chrome Remote Desktop RMM Tool File Activity
id: c3595792-bb90-5eb3-88d3-1a6979e87243
status: experimental
description: |
    Detects potential files activity of Chrome Remote Desktop RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-02
modified: 2026-09-22
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'C:\Program Files (x86)\Google\Chrome Remote Desktop\*\remoting_host.exe'
    condition: selection
falsepositives:
    - Legitimate use of Chrome Remote Desktop
level: medium
```
