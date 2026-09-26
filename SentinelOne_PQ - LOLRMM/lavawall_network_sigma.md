```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "api-ca-1.lavawall.com" or url.address contains "lavawinupdate.lavawall.com" or url.address contains "caremote1.lavawall.com") or (event.dns.request contains "api-ca-1.lavawall.com" or event.dns.request contains "lavawinupdate.lavawall.com" or event.dns.request contains "caremote1.lavawall.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Lavawall RMM Tool Network Activity
id: 64c778e9-db46-5a65-af7a-ae81d4da0462
status: experimental
description: |
    Detects potential network activity of Lavawall RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-22
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'api-ca-1.lavawall.com'
            - 'lavawinupdate.lavawall.com'
            - 'caremote1.lavawall.com'
    condition: selection
falsepositives:
    - Legitimate use of Lavawall
level: medium
```
