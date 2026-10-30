```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".internetid.ru" or url.address contains ".internetid.ru." or url.address contains ".rmansys.ru" or url.address contains ".rmansys.ru." or url.address="rmansys.ru" or url.address="rmansys.ru.") or (event.dns.request contains ".internetid.ru" or event.dns.request contains ".internetid.ru." or event.dns.request contains ".rmansys.ru" or event.dns.request contains ".rmansys.ru." or event.dns.request="rmansys.ru" or event.dns.request="rmansys.ru.")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Manipulator System RMM Tool Network Activity
id: 4ab8f777-1476-417d-8ac4-9c70c46a79ee
status: experimental
description: |
    Detects potential network activity of Remote Manipulator System RMM tool
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
            - '*.internetid.ru'
            - '*.internetid.ru.'
            - '*.rmansys.ru'
            - '*.rmansys.ru.'
            - 'rmansys.ru'
            - 'rmansys.ru.'
    condition: selection
falsepositives:
    - Legitimate use of Remote Manipulator System
level: medium
```
