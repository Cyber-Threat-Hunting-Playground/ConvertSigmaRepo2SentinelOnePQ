```sql
// Translated content (automatically translated on 16-06-2026 02:42:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "simple-help.com" or url.address contains "51.255.19.178" or url.address contains "51.255.19.179" or url.address contains "dronemaker.org" or url.address contains "telesupportgroup.com" or url.address contains "microuptime.com" or url.address contains "192.144.34.42" or url.address contains "160.191.182.41") or (event.dns.request contains "user_managed" or event.dns.request contains "simple-help.com" or event.dns.request contains "51.255.19.178" or event.dns.request contains "51.255.19.179" or event.dns.request contains "dronemaker.org" or event.dns.request contains "telesupportgroup.com" or event.dns.request contains "microuptime.com" or event.dns.request contains "192.144.34.42" or event.dns.request contains "160.191.182.41")))
```


# Original Sigma Rule:
```yaml
title: Potential SimpleHelp RMM Tool Network Activity
id: 5664ef88-4683-4f3c-9147-506eb5416d5e
status: experimental
description: |
    Detects potential network activity of SimpleHelp RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'user_managed'
            - 'simple-help.com'
            - '51.255.19.178'
            - '51.255.19.179'
            - 'dronemaker.org'
            - 'telesupportgroup.com'
            - 'microuptime.com'
            - '192.144.34.42'
            - '160.191.182.41'
    condition: selection
falsepositives:
    - Legitimate use of SimpleHelp
level: medium
```
