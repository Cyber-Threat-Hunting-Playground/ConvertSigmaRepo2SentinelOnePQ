```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".app.zecurit.com" or url.address contains ".app.zecurit.com." or url.address="app.zecurit.com" or url.address="app.zecurit.com." or url.address contains ".dms.zecurit.com" or url.address contains ".dms.zecurit.com." or url.address="dms.zecurit.com" or url.address="dms.zecurit.com." or url.address contains ".d1m8kha1zyjal6.cloudfront.net" or url.address contains ".d1m8kha1zyjal6.cloudfront.net." or url.address="d1m8kha1zyjal6.cloudfront.net" or url.address="d1m8kha1zyjal6.cloudfront.net.") or (event.dns.request contains ".app.zecurit.com" or event.dns.request contains ".app.zecurit.com." or event.dns.request="app.zecurit.com" or event.dns.request="app.zecurit.com." or event.dns.request contains ".dms.zecurit.com" or event.dns.request contains ".dms.zecurit.com." or event.dns.request="dms.zecurit.com" or event.dns.request="dms.zecurit.com." or event.dns.request contains ".d1m8kha1zyjal6.cloudfront.net" or event.dns.request contains ".d1m8kha1zyjal6.cloudfront.net." or event.dns.request="d1m8kha1zyjal6.cloudfront.net" or event.dns.request="d1m8kha1zyjal6.cloudfront.net.")))
```


# Original Sigma Rule:
```yaml
title: Potential Zecurit RMM Tool Network Activity
id: 051160f4-a097-541e-93fc-fb61eab02c69
status: experimental
description: |
    Detects potential network activity of Zecurit RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-22
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
            - '*.app.zecurit.com'
            - '*.app.zecurit.com.'
            - 'app.zecurit.com'
            - 'app.zecurit.com.'
            - '*.dms.zecurit.com'
            - '*.dms.zecurit.com.'
            - 'dms.zecurit.com'
            - 'dms.zecurit.com.'
            - '*.d1m8kha1zyjal6.cloudfront.net'
            - '*.d1m8kha1zyjal6.cloudfront.net.'
            - 'd1m8kha1zyjal6.cloudfront.net'
            - 'd1m8kha1zyjal6.cloudfront.net.'
    condition: selection
falsepositives:
    - Legitimate use of Zecurit
level: medium
```
