```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".ninja-backup.com" or url.address contains ".ninja-backup.com." or url.address contains ".ninjaone.com" or url.address contains ".ninjaone.com." or url.address contains ".ninjarmm.com" or url.address contains ".ninjarmm.com." or url.address contains ".ninjarmm.net" or url.address contains ".ninjarmm.net." or url.address contains ".resources.ninjarmm.com" or url.address contains ".resources.ninjarmm.com." or url.address contains ".rmmservice.ca" or url.address contains ".rmmservice.ca." or url.address contains ".rmmservice.com.au" or url.address contains ".rmmservice.com.au." or url.address contains ".rmmservice.eu" or url.address contains ".rmmservice.eu." or url.address="ninja-backup.com" or url.address="ninja-backup.com." or url.address="ninjaone.com" or url.address="ninjaone.com." or url.address="ninjarmm.net" or url.address="ninjarmm.net." or url.address="resources.ninjarmm.com" or url.address="resources.ninjarmm.com." or url.address="rmmservice.ca" or url.address="rmmservice.ca." or url.address="rmmservice.com.au" or url.address="rmmservice.com.au." or url.address="rmmservice.eu" or url.address="rmmservice.eu.") or (event.dns.request contains ".ninja-backup.com" or event.dns.request contains ".ninja-backup.com." or event.dns.request contains ".ninjaone.com" or event.dns.request contains ".ninjaone.com." or event.dns.request contains ".ninjarmm.com" or event.dns.request contains ".ninjarmm.com." or event.dns.request contains ".ninjarmm.net" or event.dns.request contains ".ninjarmm.net." or event.dns.request contains ".resources.ninjarmm.com" or event.dns.request contains ".resources.ninjarmm.com." or event.dns.request contains ".rmmservice.ca" or event.dns.request contains ".rmmservice.ca." or event.dns.request contains ".rmmservice.com.au" or event.dns.request contains ".rmmservice.com.au." or event.dns.request contains ".rmmservice.eu" or event.dns.request contains ".rmmservice.eu." or event.dns.request="ninja-backup.com" or event.dns.request="ninja-backup.com." or event.dns.request="ninjaone.com" or event.dns.request="ninjaone.com." or event.dns.request="ninjarmm.net" or event.dns.request="ninjarmm.net." or event.dns.request="resources.ninjarmm.com" or event.dns.request="resources.ninjarmm.com." or event.dns.request="rmmservice.ca" or event.dns.request="rmmservice.ca." or event.dns.request="rmmservice.com.au" or event.dns.request="rmmservice.com.au." or event.dns.request="rmmservice.eu" or event.dns.request="rmmservice.eu.")))
```


# Original Sigma Rule:
```yaml
title: Potential NinjaRMM RMM Tool Network Activity
id: ff3c27a2-b2d4-4e65-820f-739b97e658de
status: experimental
description: |
    Detects potential network activity of NinjaRMM RMM tool
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
            - '*.ninja-backup.com'
            - '*.ninja-backup.com.'
            - '*.ninjaone.com'
            - '*.ninjaone.com.'
            - '*.ninjarmm.com'
            - '*.ninjarmm.com.'
            - '*.ninjarmm.net'
            - '*.ninjarmm.net.'
            - '*.resources.ninjarmm.com'
            - '*.resources.ninjarmm.com.'
            - '*.rmmservice.ca'
            - '*.rmmservice.ca.'
            - '*.rmmservice.com.au'
            - '*.rmmservice.com.au.'
            - '*.rmmservice.eu'
            - '*.rmmservice.eu.'
            - 'ninja-backup.com'
            - 'ninja-backup.com.'
            - 'ninjaone.com'
            - 'ninjaone.com.'
            - 'ninjarmm.net'
            - 'ninjarmm.net.'
            - 'resources.ninjarmm.com'
            - 'resources.ninjarmm.com.'
            - 'rmmservice.ca'
            - 'rmmservice.ca.'
            - 'rmmservice.com.au'
            - 'rmmservice.com.au.'
            - 'rmmservice.eu'
            - 'rmmservice.eu.'
    condition: selection
falsepositives:
    - Legitimate use of NinjaRMM
level: medium
```
