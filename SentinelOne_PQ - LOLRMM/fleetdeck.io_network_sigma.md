```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".agentmqtt.fleetdeck.io" or url.address contains ".agentmqtt.fleetdeck.io." or url.address contains ".checkip.zmazonaws.com" or url.address contains ".checkip.zmazonaws.com." or url.address contains ".fleetdeck.io" or url.address contains ".fleetdeck.io." or url.address="agentmqtt.fleetdeck.io" or url.address="agentmqtt.fleetdeck.io." or url.address="checkip.zmazonaws.com" or url.address="checkip.zmazonaws.com." or url.address="fleetdeck.io" or url.address="fleetdeck.io.") or (event.dns.request contains ".agentmqtt.fleetdeck.io" or event.dns.request contains ".agentmqtt.fleetdeck.io." or event.dns.request contains ".checkip.zmazonaws.com" or event.dns.request contains ".checkip.zmazonaws.com." or event.dns.request contains ".fleetdeck.io" or event.dns.request contains ".fleetdeck.io." or event.dns.request="agentmqtt.fleetdeck.io" or event.dns.request="agentmqtt.fleetdeck.io." or event.dns.request="checkip.zmazonaws.com" or event.dns.request="checkip.zmazonaws.com." or event.dns.request="fleetdeck.io" or event.dns.request="fleetdeck.io.")))
```


# Original Sigma Rule:
```yaml
title: Potential FleetDeck.io RMM Tool Network Activity
id: 3a490684-6f45-489b-9941-0848466c09d6
status: experimental
description: |
    Detects potential network activity of FleetDeck.io RMM tool
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
            - '*.agentmqtt.fleetdeck.io'
            - '*.agentmqtt.fleetdeck.io.'
            - '*.checkip.zmazonaws.com'
            - '*.checkip.zmazonaws.com.'
            - '*.fleetdeck.io'
            - '*.fleetdeck.io.'
            - 'agentmqtt.fleetdeck.io'
            - 'agentmqtt.fleetdeck.io.'
            - 'checkip.zmazonaws.com'
            - 'checkip.zmazonaws.com.'
            - 'fleetdeck.io'
            - 'fleetdeck.io.'
    condition: selection
falsepositives:
    - Legitimate use of FleetDeck.io
level: medium
```
