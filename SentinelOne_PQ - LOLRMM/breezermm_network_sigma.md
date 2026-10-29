```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".breeze.app" or url.address contains ".breeze.app." or url.address contains ".breezermm.com" or url.address contains ".breezermm.com." or url.address contains ".eu.2breeze.app" or url.address contains ".eu.2breeze.app." or url.address contains ".us.2breeze.app" or url.address contains ".us.2breeze.app." or url.address="breeze.app" or url.address="breeze.app." or url.address="breezermm.com" or url.address="breezermm.com." or url.address="eu.2breeze.app" or url.address="eu.2breeze.app." or url.address="us.2breeze.app" or url.address="us.2breeze.app.") or (event.dns.request contains ".breeze.app" or event.dns.request contains ".breeze.app." or event.dns.request contains ".breezermm.com" or event.dns.request contains ".breezermm.com." or event.dns.request contains ".eu.2breeze.app" or event.dns.request contains ".eu.2breeze.app." or event.dns.request contains ".us.2breeze.app" or event.dns.request contains ".us.2breeze.app." or event.dns.request="breeze.app" or event.dns.request="breeze.app." or event.dns.request="breezermm.com" or event.dns.request="breezermm.com." or event.dns.request="eu.2breeze.app" or event.dns.request="eu.2breeze.app." or event.dns.request="us.2breeze.app" or event.dns.request="us.2breeze.app.")))
```


# Original Sigma Rule:
```yaml
title: Potential BreezeRMM RMM Tool Network Activity
id: 1047b662-3de1-5f79-889d-489dda04234a
status: experimental
description: |
    Detects potential network activity of BreezeRMM RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-08-26
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
            - '*.breeze.app'
            - '*.breeze.app.'
            - '*.breezermm.com'
            - '*.breezermm.com.'
            - '*.eu.2breeze.app'
            - '*.eu.2breeze.app.'
            - '*.us.2breeze.app'
            - '*.us.2breeze.app.'
            - 'breeze.app'
            - 'breeze.app.'
            - 'breezermm.com'
            - 'breezermm.com.'
            - 'eu.2breeze.app'
            - 'eu.2breeze.app.'
            - 'us.2breeze.app'
            - 'us.2breeze.app.'
    condition: selection
falsepositives:
    - Legitimate use of BreezeRMM
level: medium
```
