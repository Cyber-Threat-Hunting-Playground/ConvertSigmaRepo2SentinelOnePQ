```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".emcosoftware.com" or url.address contains ".emcosoftware.com." or url.address="emcosoftware.com" or url.address="emcosoftware.com.") or (event.dns.request contains ".emcosoftware.com" or event.dns.request contains ".emcosoftware.com." or event.dns.request="emcosoftware.com" or event.dns.request="emcosoftware.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential EMCO Remote Console RMM Tool Network Activity
id: 44e12795-672a-4e2d-9507-820c799bbb4e
status: experimental
description: |
    Detects potential network activity of EMCO Remote Console RMM tool
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
            - '*.emcosoftware.com'
            - '*.emcosoftware.com.'
            - 'emcosoftware.com'
            - 'emcosoftware.com.'
    condition: selection
falsepositives:
    - Legitimate use of EMCO Remote Console
level: medium
```
