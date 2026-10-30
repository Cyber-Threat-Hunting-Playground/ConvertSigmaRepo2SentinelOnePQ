```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".gateway.miradore.com" or url.address contains ".gateway.miradore.com." or url.address contains ".gerwconline.blob.core.windows.net" or url.address contains ".gerwconline.blob.core.windows.net." or url.address contains ".miradore.com" or url.address contains ".miradore.com." or url.address="gateway.miradore.com" or url.address="gateway.miradore.com." or url.address="gerwconline.blob.core.windows.net" or url.address="gerwconline.blob.core.windows.net." or url.address="miradore.com" or url.address="miradore.com.") or (event.dns.request contains ".gateway.miradore.com" or event.dns.request contains ".gateway.miradore.com." or event.dns.request contains ".gerwconline.blob.core.windows.net" or event.dns.request contains ".gerwconline.blob.core.windows.net." or event.dns.request contains ".miradore.com" or event.dns.request contains ".miradore.com." or event.dns.request="gateway.miradore.com" or event.dns.request="gateway.miradore.com." or event.dns.request="gerwconline.blob.core.windows.net" or event.dns.request="gerwconline.blob.core.windows.net." or event.dns.request="miradore.com" or event.dns.request="miradore.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Miradore RMM Tool Network Activity
id: 15edd57b-00a7-53f9-8d3c-0b8679e0360d
status: experimental
description: |
    Detects potential network activity of Miradore RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - '*.gateway.miradore.com'
            - '*.gateway.miradore.com.'
            - '*.gerwconline.blob.core.windows.net'
            - '*.gerwconline.blob.core.windows.net.'
            - '*.miradore.com'
            - '*.miradore.com.'
            - 'gateway.miradore.com'
            - 'gateway.miradore.com.'
            - 'gerwconline.blob.core.windows.net'
            - 'gerwconline.blob.core.windows.net.'
            - 'miradore.com'
            - 'miradore.com.'
    condition: selection
falsepositives:
    - Legitimate use of Miradore
level: medium
```
