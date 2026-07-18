```sql
// Translated content (automatically translated on 18-07-2026 01:22:39):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".adobeconnect.com" or event.dns.request contains ".adobeconnect.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Adobe Connect RMM Tool Network Activity
id: c32a974a-ab36-4e6d-862f-e36c129dd140
status: experimental
description: |
    Detects potential network activity of Adobe Connect RMM tool
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
        DestinationHostname|endswith: '*.adobeconnect.com'
    condition: selection
falsepositives:
    - Legitimate use of Adobe Connect
level: medium
```
