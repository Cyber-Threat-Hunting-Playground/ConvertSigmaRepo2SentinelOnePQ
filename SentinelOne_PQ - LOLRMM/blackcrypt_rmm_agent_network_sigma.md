```sql
// Translated content (automatically translated on 24-09-2026 02:05:20):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "blackcryptknight.com" or event.dns.request contains "blackcryptknight.com"))
```


# Original Sigma Rule:
```yaml
title: Potential BlackCrypt RMM Agent RMM Tool Network Activity
id: a3c3ce4e-773c-5df5-9776-6a85222e5758
status: experimental
description: |
    Detects potential network activity of BlackCrypt RMM Agent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith: 'blackcryptknight.com'
    condition: selection
falsepositives:
    - Legitimate use of BlackCrypt RMM Agent
level: medium
```
