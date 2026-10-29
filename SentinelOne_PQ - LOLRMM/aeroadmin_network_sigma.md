```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".aeroadmin.com" or url.address contains ".aeroadmin.com." or url.address="aeroadmin.com" or url.address="aeroadmin.com." or url.address="auth*.aeroadmin.com" or url.address="auth*.aeroadmin.com.") or (event.dns.request contains ".aeroadmin.com" or event.dns.request contains ".aeroadmin.com." or event.dns.request="aeroadmin.com" or event.dns.request="aeroadmin.com." or event.dns.request="auth*.aeroadmin.com" or event.dns.request="auth*.aeroadmin.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential AeroAdmin RMM Tool Network Activity
id: 0b37a0c4-a652-4902-b649-735b7a6139bb
status: experimental
description: |
    Detects potential network activity of AeroAdmin RMM tool
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
            - '*.aeroadmin.com'
            - '*.aeroadmin.com.'
            - 'aeroadmin.com'
            - 'aeroadmin.com.'
            - 'auth*.aeroadmin.com'
            - 'auth*.aeroadmin.com.'
    condition: selection
falsepositives:
    - Legitimate use of AeroAdmin
level: medium
```
