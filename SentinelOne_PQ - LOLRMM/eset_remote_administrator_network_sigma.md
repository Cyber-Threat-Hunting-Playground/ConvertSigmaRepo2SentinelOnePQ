```sql
// Translated content (automatically translated on 01-07-2026 02:28:53):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential ESET Remote Administrator RMM Tool Network Activity
id: 1f07c61b-b329-4814-af2a-de7c4bf3e993
status: experimental
description: |
    Detects potential network activity of ESET Remote Administrator RMM tool
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
        DestinationHostname|endswith: 'user_managed'
    condition: selection
falsepositives:
    - Legitimate use of ESET Remote Administrator
level: medium
```
