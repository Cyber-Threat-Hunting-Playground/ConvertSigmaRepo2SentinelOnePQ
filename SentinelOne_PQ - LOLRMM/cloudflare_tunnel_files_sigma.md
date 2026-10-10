```sql
// Translated content (automatically translated on 10-10-2026 03:12:59):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\ProgramData\\cloudflared\*" or tgt.file.path contains "C:\\Windows\\System32\\config\\systemprofile\\.cloudflared\*" or tgt.file.path contains "C:\\Users\*\\.cloudflared\*"))
```


# Original Sigma Rule:
```yaml
title: Potential CloudFlare Tunnel RMM Tool File Activity
id: d05716b2-c567-5a87-9d05-54e2205551d9
status: experimental
description: |
    Detects potential files activity of CloudFlare Tunnel RMM tool
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
            - 'C:\ProgramData\cloudflared\*'
            - 'C:\Windows\System32\config\systemprofile\.cloudflared\*'
            - 'C:\Users\*\.cloudflared\*'
    condition: selection
falsepositives:
    - Legitimate use of CloudFlare Tunnel
level: medium
```
