```sql
// Translated content (automatically translated on 10-10-2026 03:12:59):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "geo.netsupportsoftware.com" or url.address contains ".netsupportmanager.com" or url.address contains "netsupportmanager.com" or url.address contains "paternal-angrily.com") or (event.dns.request contains "geo.netsupportsoftware.com" or event.dns.request contains ".netsupportmanager.com" or event.dns.request contains "netsupportmanager.com" or event.dns.request contains "paternal-angrily.com")))
```


# Original Sigma Rule:
```yaml
title: Potential NetSupport Manager RMM Tool Network Activity
id: 8097d92a-5bbf-4dcc-8dc0-28e0726f5ae3
status: experimental
description: |
    Detects potential network activity of NetSupport Manager RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-10-09
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'geo.netsupportsoftware.com'
            - '*.netsupportmanager.com'
            - 'netsupportmanager.com'
            - 'paternal-angrily.com'
    condition: selection
falsepositives:
    - Legitimate use of NetSupport Manager
level: medium
```
