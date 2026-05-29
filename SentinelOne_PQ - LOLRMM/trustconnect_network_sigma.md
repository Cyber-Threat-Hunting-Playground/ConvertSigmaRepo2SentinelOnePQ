```sql
// Translated content (automatically translated on 29-05-2026 02:05:07):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "trustconnectsoftware.com" or url.address contains "trustconnectsoftware.com" or url.address contains "trustconnectsoftware.com" or url.address contains "trustconnectsoftware.com" or url.address contains "networkservice.cyou") or (event.dns.request contains "trustconnectsoftware.com" or event.dns.request contains "trustconnectsoftware.com" or event.dns.request contains "trustconnectsoftware.com" or event.dns.request contains "trustconnectsoftware.com" or event.dns.request contains "networkservice.cyou")))
```


# Original Sigma Rule:
```yaml
title: Potential TrustConnect RMM Tool Network Activity
id: 73557a7b-333e-518d-b49d-e865281010c7
status: experimental
description: |
    Detects potential network activity of TrustConnect RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'trustconnectsoftware.com'
            - 'trustconnectsoftware.com'
            - 'trustconnectsoftware.com'
            - 'trustconnectsoftware.com'
            - 'networkservice.cyou'
    condition: selection
falsepositives:
    - Legitimate use of TrustConnect
level: medium
```
