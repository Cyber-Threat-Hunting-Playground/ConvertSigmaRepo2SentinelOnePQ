```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".vector-networks.com" or url.address contains ".vector-networks.com." or url.address contains ".vizor.cloud" or url.address contains ".vizor.cloud." or url.address contains ".www.vector-networks.com" or url.address contains ".www.vector-networks.com." or url.address contains ".www.vizor.cloud" or url.address contains ".www.vizor.cloud." or url.address="vector-networks.com" or url.address="vector-networks.com." or url.address="vizor.cloud" or url.address="vizor.cloud." or url.address="www.vector-networks.com" or url.address="www.vector-networks.com." or url.address="www.vizor.cloud" or url.address="www.vizor.cloud." or url.address contains ".mail.metaquest.com" or url.address contains ".mail.metaquest.com." or url.address contains ".metaquest.com" or url.address contains ".metaquest.com." or url.address contains ".www.metaquest.com" or url.address contains ".www.metaquest.com." or url.address="mail.metaquest.com" or url.address="mail.metaquest.com." or url.address="metaquest.com" or url.address="metaquest.com." or url.address="www.metaquest.com" or url.address="www.metaquest.com." or url.address contains ".downloads.vector-networks.com" or url.address contains ".downloads.vector-networks.com." or url.address="downloads.vector-networks.com" or url.address="downloads.vector-networks.com.") or (event.dns.request contains ".vector-networks.com" or event.dns.request contains ".vector-networks.com." or event.dns.request contains ".vizor.cloud" or event.dns.request contains ".vizor.cloud." or event.dns.request contains ".www.vector-networks.com" or event.dns.request contains ".www.vector-networks.com." or event.dns.request contains ".www.vizor.cloud" or event.dns.request contains ".www.vizor.cloud." or event.dns.request="vector-networks.com" or event.dns.request="vector-networks.com." or event.dns.request="vizor.cloud" or event.dns.request="vizor.cloud." or event.dns.request="www.vector-networks.com" or event.dns.request="www.vector-networks.com." or event.dns.request="www.vizor.cloud" or event.dns.request="www.vizor.cloud." or event.dns.request contains ".mail.metaquest.com" or event.dns.request contains ".mail.metaquest.com." or event.dns.request contains ".metaquest.com" or event.dns.request contains ".metaquest.com." or event.dns.request contains ".www.metaquest.com" or event.dns.request contains ".www.metaquest.com." or event.dns.request="mail.metaquest.com" or event.dns.request="mail.metaquest.com." or event.dns.request="metaquest.com" or event.dns.request="metaquest.com." or event.dns.request="www.metaquest.com" or event.dns.request="www.metaquest.com." or event.dns.request contains ".downloads.vector-networks.com" or event.dns.request contains ".downloads.vector-networks.com." or event.dns.request="downloads.vector-networks.com" or event.dns.request="downloads.vector-networks.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential VIZOR RMM Tool Network Activity
id: 7f21b9c6-6737-5320-a983-09a5e659007b
status: experimental
description: |
    Detects potential network activity of VIZOR RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - '*.vector-networks.com'
            - '*.vector-networks.com.'
            - '*.vizor.cloud'
            - '*.vizor.cloud.'
            - '*.www.vector-networks.com'
            - '*.www.vector-networks.com.'
            - '*.www.vizor.cloud'
            - '*.www.vizor.cloud.'
            - 'vector-networks.com'
            - 'vector-networks.com.'
            - 'vizor.cloud'
            - 'vizor.cloud.'
            - 'www.vector-networks.com'
            - 'www.vector-networks.com.'
            - 'www.vizor.cloud'
            - 'www.vizor.cloud.'
            - '*.mail.metaquest.com'
            - '*.mail.metaquest.com.'
            - '*.metaquest.com'
            - '*.metaquest.com.'
            - '*.www.metaquest.com'
            - '*.www.metaquest.com.'
            - 'mail.metaquest.com'
            - 'mail.metaquest.com.'
            - 'metaquest.com'
            - 'metaquest.com.'
            - 'www.metaquest.com'
            - 'www.metaquest.com.'
            - '*.downloads.vector-networks.com'
            - '*.downloads.vector-networks.com.'
            - 'downloads.vector-networks.com'
            - 'downloads.vector-networks.com.'
    condition: selection
falsepositives:
    - Legitimate use of VIZOR
level: medium
```
