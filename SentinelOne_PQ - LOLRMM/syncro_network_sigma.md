```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".app.kabuto.io" or url.address contains ".app.kabuto.io." or url.address contains ".attachments.servably.com" or url.address contains ".attachments.servably.com." or url.address contains ".kabuto.io" or url.address contains ".kabuto.io." or url.address contains ".kabutoservices.com" or url.address contains ".kabutoservices.com." or url.address contains ".ld.aurelius.host" or url.address contains ".ld.aurelius.host." or url.address contains ".repairshopr.com" or url.address contains ".repairshopr.com." or url.address contains ".servably.com" or url.address contains ".servably.com." or url.address contains ".syncroapi.com" or url.address contains ".syncroapi.com." or url.address contains ".syncromsp.com" or url.address contains ".syncromsp.com." or url.address="app.kabuto.io" or url.address="app.kabuto.io." or url.address="attachments.servably.com" or url.address="attachments.servably.com." or url.address="kabuto.io" or url.address="kabuto.io." or url.address="kabutoservices.com" or url.address="kabutoservices.com." or url.address="ld.aurelius.host" or url.address="ld.aurelius.host." or url.address="repairshopr.com" or url.address="repairshopr.com." or url.address="servably.com" or url.address="servably.com." or url.address="syncromsp.com" or url.address="syncromsp.com.") or (event.dns.request contains ".app.kabuto.io" or event.dns.request contains ".app.kabuto.io." or event.dns.request contains ".attachments.servably.com" or event.dns.request contains ".attachments.servably.com." or event.dns.request contains ".kabuto.io" or event.dns.request contains ".kabuto.io." or event.dns.request contains ".kabutoservices.com" or event.dns.request contains ".kabutoservices.com." or event.dns.request contains ".ld.aurelius.host" or event.dns.request contains ".ld.aurelius.host." or event.dns.request contains ".repairshopr.com" or event.dns.request contains ".repairshopr.com." or event.dns.request contains ".servably.com" or event.dns.request contains ".servably.com." or event.dns.request contains ".syncroapi.com" or event.dns.request contains ".syncroapi.com." or event.dns.request contains ".syncromsp.com" or event.dns.request contains ".syncromsp.com." or event.dns.request="app.kabuto.io" or event.dns.request="app.kabuto.io." or event.dns.request="attachments.servably.com" or event.dns.request="attachments.servably.com." or event.dns.request="kabuto.io" or event.dns.request="kabuto.io." or event.dns.request="kabutoservices.com" or event.dns.request="kabutoservices.com." or event.dns.request="ld.aurelius.host" or event.dns.request="ld.aurelius.host." or event.dns.request="repairshopr.com" or event.dns.request="repairshopr.com." or event.dns.request="servably.com" or event.dns.request="servably.com." or event.dns.request="syncromsp.com" or event.dns.request="syncromsp.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Syncro RMM Tool Network Activity
id: 24964039-9f3a-40ac-a2e0-1a346b3278f7
status: experimental
description: |
    Detects potential network activity of Syncro RMM tool
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
            - '*.app.kabuto.io'
            - '*.app.kabuto.io.'
            - '*.attachments.servably.com'
            - '*.attachments.servably.com.'
            - '*.kabuto.io'
            - '*.kabuto.io.'
            - '*.kabutoservices.com'
            - '*.kabutoservices.com.'
            - '*.ld.aurelius.host'
            - '*.ld.aurelius.host.'
            - '*.repairshopr.com'
            - '*.repairshopr.com.'
            - '*.servably.com'
            - '*.servably.com.'
            - '*.syncroapi.com'
            - '*.syncroapi.com.'
            - '*.syncromsp.com'
            - '*.syncromsp.com.'
            - 'app.kabuto.io'
            - 'app.kabuto.io.'
            - 'attachments.servably.com'
            - 'attachments.servably.com.'
            - 'kabuto.io'
            - 'kabuto.io.'
            - 'kabutoservices.com'
            - 'kabutoservices.com.'
            - 'ld.aurelius.host'
            - 'ld.aurelius.host.'
            - 'repairshopr.com'
            - 'repairshopr.com.'
            - 'servably.com'
            - 'servably.com.'
            - 'syncromsp.com'
            - 'syncromsp.com.'
    condition: selection
falsepositives:
    - Legitimate use of Syncro
level: medium
```
