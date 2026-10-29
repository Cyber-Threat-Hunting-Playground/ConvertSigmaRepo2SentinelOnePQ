```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".client-api.aweray.com" or url.address contains ".client-api.aweray.com." or url.address="asapi*.aweray.net" or url.address="asapi*.aweray.net." or url.address="client-api.aweray.com" or url.address="client-api.aweray.com.") or (event.dns.request contains ".client-api.aweray.com" or event.dns.request contains ".client-api.aweray.com." or event.dns.request="asapi*.aweray.net" or event.dns.request="asapi*.aweray.net." or event.dns.request="client-api.aweray.com" or event.dns.request="client-api.aweray.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential AweRay RMM Tool Network Activity
id: 4bcb82fa-7d77-4720-948a-c445b9fb7976
status: experimental
description: |
    Detects potential network activity of AweRay RMM tool
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
            - '*.client-api.aweray.com'
            - '*.client-api.aweray.com.'
            - 'asapi*.aweray.net'
            - 'asapi*.aweray.net.'
            - 'client-api.aweray.com'
            - 'client-api.aweray.com.'
    condition: selection
falsepositives:
    - Legitimate use of AweRay
level: medium
```
