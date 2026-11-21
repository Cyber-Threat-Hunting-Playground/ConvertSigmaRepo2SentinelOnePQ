```sql
// Translated content (automatically translated on 21-11-2026 04:41:38):
event.category="file" and (endpoint.os="windows" and tgt.file.path contains "C:\\ProgramData\\JWrapper-Remote Access\\")
```


# Original Sigma Rule:
```yaml
title: Potential SimpleHelp RMM Tool File Activity
id: dcfe4fa2-0f13-51fc-b64b-6ea408c804a3
status: experimental
description: |
    Detects potential files activity of SimpleHelp RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-10-28
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'C:\ProgramData\JWrapper-Remote Access\'
    condition: selection
falsepositives:
    - Legitimate use of SimpleHelp
level: medium
```
