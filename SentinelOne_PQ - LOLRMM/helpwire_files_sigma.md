```sql
// Translated content (automatically translated on 23-09-2026 02:18:07):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "helpwire.exe" or tgt.file.path contains "HelpWire Quick.exe" or tgt.file.path contains "HelpWire.lnk" or tgt.file.path contains "HelpWire Unattended Access.lnk"))
```


# Original Sigma Rule:
```yaml
title: Potential HelpWire RMM Tool File Activity
id: 0b9389a7-719d-5d4c-b429-2b2a70d598da
status: experimental
description: |
    Detects potential files activity of HelpWire RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-06-11
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
            - 'helpwire.exe'
            - 'HelpWire Quick.exe'
            - 'HelpWire.lnk'
            - 'HelpWire Unattended Access.lnk'
    condition: selection
falsepositives:
    - Legitimate use of HelpWire
level: medium
```
