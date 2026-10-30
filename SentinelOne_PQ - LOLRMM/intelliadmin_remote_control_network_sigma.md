```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".intelliadmin.com" or url.address contains ".intelliadmin.com.") or (event.dns.request contains ".intelliadmin.com" or event.dns.request contains ".intelliadmin.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential IntelliAdmin Remote Control RMM Tool Network Activity
id: 9fcf8472-8fab-4b74-8074-aae4143ddfa3
status: experimental
description: |
    Detects potential network activity of IntelliAdmin Remote Control RMM tool
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
    category: network_connection
detection:
    selection:
        DestinationHostname:
            - '*.intelliadmin.com'
            - '*.intelliadmin.com.'
    condition: selection
falsepositives:
    - Legitimate use of IntelliAdmin Remote Control
level: medium
```
