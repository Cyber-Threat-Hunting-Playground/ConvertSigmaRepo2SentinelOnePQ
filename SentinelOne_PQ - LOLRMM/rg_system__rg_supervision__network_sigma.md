```sql
// Translated content (automatically translated on 24-09-2026 02:05:20):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "lisa.rg-supervision.com" or url.address contains "api.rg-supervision.com" or url.address contains "dashboard.rg-supervision.com") or (event.dns.request contains "lisa.rg-supervision.com" or event.dns.request contains "api.rg-supervision.com" or event.dns.request contains "dashboard.rg-supervision.com")))
```


# Original Sigma Rule:
```yaml
title: Potential RG System (RG Supervision) RMM Tool Network Activity
id: 36860a70-0e43-5fe9-8521-f79fbd767118
status: experimental
description: |
    Detects potential network activity of RG System (RG Supervision) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'lisa.rg-supervision.com'
            - 'api.rg-supervision.com'
            - 'dashboard.rg-supervision.com'
    condition: selection
falsepositives:
    - Legitimate use of RG System (RG Supervision)
level: medium
```
