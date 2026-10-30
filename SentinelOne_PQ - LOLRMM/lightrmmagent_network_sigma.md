```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".light-rmm-monitor-20260825.azurewebsites.net" or url.address contains ".light-rmm-monitor-20260825.azurewebsites.net." or url.address="light-rmm-monitor-20260825.azurewebsites.net" or url.address="light-rmm-monitor-20260825.azurewebsites.net.") or (event.dns.request contains ".light-rmm-monitor-20260825.azurewebsites.net" or event.dns.request contains ".light-rmm-monitor-20260825.azurewebsites.net." or event.dns.request="light-rmm-monitor-20260825.azurewebsites.net" or event.dns.request="light-rmm-monitor-20260825.azurewebsites.net.")))
```


# Original Sigma Rule:
```yaml
title: Potential LightRmmAgent RMM Tool Network Activity
id: 98b58865-529f-569d-8681-d79861883de1
status: experimental
description: |
    Detects potential network activity of LightRmmAgent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
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
            - '*.light-rmm-monitor-20260825.azurewebsites.net'
            - '*.light-rmm-monitor-20260825.azurewebsites.net.'
            - 'light-rmm-monitor-20260825.azurewebsites.net'
            - 'light-rmm-monitor-20260825.azurewebsites.net.'
    condition: selection
falsepositives:
    - Legitimate use of LightRmmAgent
level: medium
```
