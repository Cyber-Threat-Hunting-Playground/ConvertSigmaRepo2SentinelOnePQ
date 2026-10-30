```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".account.flexihub.com" or url.address contains ".account.flexihub.com." or url.address contains ".api.helpwire.app" or url.address contains ".api.helpwire.app." or url.address contains ".get.helpwire.app" or url.address contains ".get.helpwire.app." or url.address contains ".helpwire.app" or url.address contains ".helpwire.app." or url.address contains ".staging.helpwire.app" or url.address contains ".staging.helpwire.app." or url.address="account.flexihub.com" or url.address="account.flexihub.com." or url.address="api.helpwire.app" or url.address="api.helpwire.app." or url.address="get.helpwire.app" or url.address="get.helpwire.app." or url.address="helpwire.app" or url.address="helpwire.app." or url.address="staging.helpwire.app" or url.address="staging.helpwire.app." or url.address contains ".stun.helpwire.app" or url.address contains ".stun.helpwire.app." or url.address="stun.helpwire.app" or url.address="stun.helpwire.app.") or (event.dns.request contains ".account.flexihub.com" or event.dns.request contains ".account.flexihub.com." or event.dns.request contains ".api.helpwire.app" or event.dns.request contains ".api.helpwire.app." or event.dns.request contains ".get.helpwire.app" or event.dns.request contains ".get.helpwire.app." or event.dns.request contains ".helpwire.app" or event.dns.request contains ".helpwire.app." or event.dns.request contains ".staging.helpwire.app" or event.dns.request contains ".staging.helpwire.app." or event.dns.request="account.flexihub.com" or event.dns.request="account.flexihub.com." or event.dns.request="api.helpwire.app" or event.dns.request="api.helpwire.app." or event.dns.request="get.helpwire.app" or event.dns.request="get.helpwire.app." or event.dns.request="helpwire.app" or event.dns.request="helpwire.app." or event.dns.request="staging.helpwire.app" or event.dns.request="staging.helpwire.app." or event.dns.request contains ".stun.helpwire.app" or event.dns.request contains ".stun.helpwire.app." or event.dns.request="stun.helpwire.app" or event.dns.request="stun.helpwire.app.")))
```


# Original Sigma Rule:
```yaml
title: Potential HelpWire RMM Tool Network Activity
id: 825d9be6-fbf9-511e-a9ab-0ead41cc18ff
status: experimental
description: |
    Detects potential network activity of HelpWire RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-06-11
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
            - '*.account.flexihub.com'
            - '*.account.flexihub.com.'
            - '*.api.helpwire.app'
            - '*.api.helpwire.app.'
            - '*.get.helpwire.app'
            - '*.get.helpwire.app.'
            - '*.helpwire.app'
            - '*.helpwire.app.'
            - '*.staging.helpwire.app'
            - '*.staging.helpwire.app.'
            - 'account.flexihub.com'
            - 'account.flexihub.com.'
            - 'api.helpwire.app'
            - 'api.helpwire.app.'
            - 'get.helpwire.app'
            - 'get.helpwire.app.'
            - 'helpwire.app'
            - 'helpwire.app.'
            - 'staging.helpwire.app'
            - 'staging.helpwire.app.'
            - '*.stun.helpwire.app'
            - '*.stun.helpwire.app.'
            - 'stun.helpwire.app'
            - 'stun.helpwire.app.'
    condition: selection
falsepositives:
    - Legitimate use of HelpWire
level: medium
```
