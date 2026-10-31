```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".api.rustdesk.com" or url.address contains ".api.rustdesk.com." or url.address contains ".rs-ny.rustdesk.com" or url.address contains ".rs-ny.rustdesk.com." or url.address contains ".rustdesk.com" or url.address contains ".rustdesk.com." or url.address contains ".web.rustdesk.com" or url.address contains ".web.rustdesk.com." or url.address="api.rustdesk.com" or url.address="api.rustdesk.com." or url.address="rs-ny.rustdesk.com" or url.address="rs-ny.rustdesk.com." or url.address="rustdesk.com" or url.address="rustdesk.com." or url.address="web.rustdesk.com" or url.address="web.rustdesk.com.") or (event.dns.request contains ".api.rustdesk.com" or event.dns.request contains ".api.rustdesk.com." or event.dns.request contains ".rs-ny.rustdesk.com" or event.dns.request contains ".rs-ny.rustdesk.com." or event.dns.request contains ".rustdesk.com" or event.dns.request contains ".rustdesk.com." or event.dns.request contains ".web.rustdesk.com" or event.dns.request contains ".web.rustdesk.com." or event.dns.request="api.rustdesk.com" or event.dns.request="api.rustdesk.com." or event.dns.request="rs-ny.rustdesk.com" or event.dns.request="rs-ny.rustdesk.com." or event.dns.request="rustdesk.com" or event.dns.request="rustdesk.com." or event.dns.request="web.rustdesk.com" or event.dns.request="web.rustdesk.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential RustDesk RMM Tool Network Activity
id: 56f0c5a9-a83b-41ec-b9cf-f90c69b2e142
status: experimental
description: |
    Detects potential network activity of RustDesk RMM tool
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
            - '*.api.rustdesk.com'
            - '*.api.rustdesk.com.'
            - '*.rs-ny.rustdesk.com'
            - '*.rs-ny.rustdesk.com.'
            - '*.rustdesk.com'
            - '*.rustdesk.com.'
            - '*.web.rustdesk.com'
            - '*.web.rustdesk.com.'
            - 'api.rustdesk.com'
            - 'api.rustdesk.com.'
            - 'rs-ny.rustdesk.com'
            - 'rs-ny.rustdesk.com.'
            - 'rustdesk.com'
            - 'rustdesk.com.'
            - 'web.rustdesk.com'
            - 'web.rustdesk.com.'
    condition: selection
falsepositives:
    - Legitimate use of RustDesk
level: medium
```
