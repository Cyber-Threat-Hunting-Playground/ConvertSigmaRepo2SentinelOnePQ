```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".connectwise.com" or url.address contains ".connectwise.com." or url.address contains ".control.connectwise.com" or url.address contains ".control.connectwise.com." or url.address contains ".screenconnect.com" or url.address contains ".screenconnect.com." or url.address="control.connectwise.com" or url.address="control.connectwise.com." or url.address="instance-*-relay.screenconnect.com" or url.address="instance-*-relay.screenconnect.com.") or (event.dns.request contains ".connectwise.com" or event.dns.request contains ".connectwise.com." or event.dns.request contains ".control.connectwise.com" or event.dns.request contains ".control.connectwise.com." or event.dns.request contains ".screenconnect.com" or event.dns.request contains ".screenconnect.com." or event.dns.request="control.connectwise.com" or event.dns.request="control.connectwise.com." or event.dns.request="instance-*-relay.screenconnect.com" or event.dns.request="instance-*-relay.screenconnect.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenConnect RMM Tool Network Activity
id: 74f512be-1adb-411e-962f-9f759996e8fe
status: experimental
description: |
    Detects potential network activity of ScreenConnect RMM tool
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
            - '*.connectwise.com'
            - '*.connectwise.com.'
            - '*.control.connectwise.com'
            - '*.control.connectwise.com.'
            - '*.screenconnect.com'
            - '*.screenconnect.com.'
            - 'control.connectwise.com'
            - 'control.connectwise.com.'
            - 'instance-*-relay.screenconnect.com'
            - 'instance-*-relay.screenconnect.com.'
    condition: selection
falsepositives:
    - Legitimate use of ScreenConnect
level: medium
```
