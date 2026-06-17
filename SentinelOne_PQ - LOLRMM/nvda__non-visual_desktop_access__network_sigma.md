```sql
// Translated content (automatically translated on 17-06-2026 02:38:58):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "nvaccess.org" or url.address contains ".nvaccess.org") or (event.dns.request contains "nvaccess.org" or event.dns.request contains ".nvaccess.org")))
```


# Original Sigma Rule:
```yaml
title: Potential NVDA (Non-Visual Desktop Access) RMM Tool Network Activity
id: 814532f6-267d-5e39-b304-2ea58274997d
status: experimental
description: |
    Detects potential network activity of NVDA (Non-Visual Desktop Access) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'nvaccess.org'
            - '*.nvaccess.org'
    condition: selection
falsepositives:
    - Legitimate use of NVDA (Non-Visual Desktop Access)
level: medium
```
