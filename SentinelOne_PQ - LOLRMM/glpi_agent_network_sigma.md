```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".glpi-project.org" or url.address contains ".glpi-project.org." or url.address contains ".www.glpi-project.org" or url.address contains ".www.glpi-project.org." or url.address="glpi-project.org" or url.address="glpi-project.org." or url.address="www.glpi-project.org" or url.address="www.glpi-project.org." or url.address contains ".nightly.glpi-project.org" or url.address contains ".nightly.glpi-project.org." or url.address="nightly.glpi-project.org" or url.address="nightly.glpi-project.org." or url.address contains ".forum.glpi-project.org" or url.address contains ".forum.glpi-project.org." or url.address="forum.glpi-project.org" or url.address="forum.glpi-project.org." or url.address contains ".glpi-network.com" or url.address contains ".glpi-network.com." or url.address contains ".services.glpi-network.com" or url.address contains ".services.glpi-network.com." or url.address="glpi-network.com" or url.address="glpi-network.com." or url.address="services.glpi-network.com" or url.address="services.glpi-network.com.") or (event.dns.request contains ".glpi-project.org" or event.dns.request contains ".glpi-project.org." or event.dns.request contains ".www.glpi-project.org" or event.dns.request contains ".www.glpi-project.org." or event.dns.request="glpi-project.org" or event.dns.request="glpi-project.org." or event.dns.request="www.glpi-project.org" or event.dns.request="www.glpi-project.org." or event.dns.request contains ".nightly.glpi-project.org" or event.dns.request contains ".nightly.glpi-project.org." or event.dns.request="nightly.glpi-project.org" or event.dns.request="nightly.glpi-project.org." or event.dns.request contains ".forum.glpi-project.org" or event.dns.request contains ".forum.glpi-project.org." or event.dns.request="forum.glpi-project.org" or event.dns.request="forum.glpi-project.org." or event.dns.request contains ".glpi-network.com" or event.dns.request contains ".glpi-network.com." or event.dns.request contains ".services.glpi-network.com" or event.dns.request contains ".services.glpi-network.com." or event.dns.request="glpi-network.com" or event.dns.request="glpi-network.com." or event.dns.request="services.glpi-network.com" or event.dns.request="services.glpi-network.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential GLPI Agent RMM Tool Network Activity
id: 47e1cc56-2677-52dc-b1ad-b6d24b617c25
status: experimental
description: |
    Detects potential network activity of GLPI Agent RMM tool
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
            - '*.glpi-project.org'
            - '*.glpi-project.org.'
            - '*.www.glpi-project.org'
            - '*.www.glpi-project.org.'
            - 'glpi-project.org'
            - 'glpi-project.org.'
            - 'www.glpi-project.org'
            - 'www.glpi-project.org.'
            - '*.nightly.glpi-project.org'
            - '*.nightly.glpi-project.org.'
            - 'nightly.glpi-project.org'
            - 'nightly.glpi-project.org.'
            - '*.forum.glpi-project.org'
            - '*.forum.glpi-project.org.'
            - 'forum.glpi-project.org'
            - 'forum.glpi-project.org.'
            - '*.glpi-network.com'
            - '*.glpi-network.com.'
            - '*.services.glpi-network.com'
            - '*.services.glpi-network.com.'
            - 'glpi-network.com'
            - 'glpi-network.com.'
            - 'services.glpi-network.com'
            - 'services.glpi-network.com.'
    condition: selection
falsepositives:
    - Legitimate use of GLPI Agent
level: medium
```
