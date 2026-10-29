```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".beanywhere.com" or url.address contains ".beanywhere.com." or url.address="beanywhere.com" or url.address="beanywhere.com.") or (event.dns.request contains ".beanywhere.com" or event.dns.request contains ".beanywhere.com." or event.dns.request="beanywhere.com" or event.dns.request="beanywhere.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential BeAnyWhere RMM Tool Network Activity
id: e68427eb-6abc-4dbe-85b9-0ca93e3742ed
status: experimental
description: |
    Detects potential network activity of BeAnyWhere RMM tool
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
            - '*.beanywhere.com'
            - '*.beanywhere.com.'
            - 'beanywhere.com'
            - 'beanywhere.com.'
    condition: selection
falsepositives:
    - Legitimate use of BeAnyWhere
level: medium
```
