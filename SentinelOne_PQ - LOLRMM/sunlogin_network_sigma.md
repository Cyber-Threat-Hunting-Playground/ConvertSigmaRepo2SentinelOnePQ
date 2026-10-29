```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".client.oray.net" or url.address contains ".client.oray.net." or url.address contains ".sunlogin.oray.com" or url.address contains ".sunlogin.oray.com." or url.address="client.oray.net" or url.address="client.oray.net." or url.address="sunlogin.oray.com" or url.address="sunlogin.oray.com.") or (event.dns.request contains ".client.oray.net" or event.dns.request contains ".client.oray.net." or event.dns.request contains ".sunlogin.oray.com" or event.dns.request contains ".sunlogin.oray.com." or event.dns.request="client.oray.net" or event.dns.request="client.oray.net." or event.dns.request="sunlogin.oray.com" or event.dns.request="sunlogin.oray.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential SunLogin RMM Tool Network Activity
id: 3e298919-e799-44b3-8122-35d2b02baa51
status: experimental
description: |
    Detects potential network activity of SunLogin RMM tool
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
            - '*.client.oray.net'
            - '*.client.oray.net.'
            - '*.sunlogin.oray.com'
            - '*.sunlogin.oray.com.'
            - 'client.oray.net'
            - 'client.oray.net.'
            - 'sunlogin.oray.com'
            - 'sunlogin.oray.com.'
    condition: selection
falsepositives:
    - Legitimate use of SunLogin
level: medium
```
