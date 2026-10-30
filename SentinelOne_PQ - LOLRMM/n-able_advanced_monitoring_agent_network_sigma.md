```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".beanywhere.com" or url.address contains ".beanywhere.com." or url.address contains ".cloudbackup.management" or url.address contains ".cloudbackup.management." or url.address contains ".logicnow.com" or url.address contains ".logicnow.com." or url.address contains ".n-able.com" or url.address contains ".n-able.com." or url.address contains ".remote.management" or url.address contains ".remote.management." or url.address contains ".swi-tc.com" or url.address contains ".swi-tc.com." or url.address contains ".system-monitor.com" or url.address contains ".system-monitor.com." or url.address contains ".systemmonitor.co.uk" or url.address contains ".systemmonitor.co.uk." or url.address contains ".systemmonitor.eu.com" or url.address contains ".systemmonitor.eu.com." or url.address contains ".systemmonitor.us" or url.address contains ".systemmonitor.us." or url.address contains ".systemmonitor.us.cdn.cloudflare.net" or url.address contains ".systemmonitor.us.cdn.cloudflare.net." or url.address="beanywhere.com" or url.address="beanywhere.com." or url.address="cloudbackup.management" or url.address="cloudbackup.management." or url.address="logicnow.com" or url.address="logicnow.com." or url.address="n-able.com" or url.address="n-able.com." or url.address="remote.management" or url.address="remote.management." or url.address="system-monitor.com" or url.address="system-monitor.com." or url.address="systemmonitor.co.uk" or url.address="systemmonitor.co.uk." or url.address="systemmonitor.eu.com" or url.address="systemmonitor.eu.com." or url.address="systemmonitor.us" or url.address="systemmonitor.us." or url.address="systemmonitor.us.cdn.cloudflare.net" or url.address="systemmonitor.us.cdn.cloudflare.net.") or (event.dns.request contains ".beanywhere.com" or event.dns.request contains ".beanywhere.com." or event.dns.request contains ".cloudbackup.management" or event.dns.request contains ".cloudbackup.management." or event.dns.request contains ".logicnow.com" or event.dns.request contains ".logicnow.com." or event.dns.request contains ".n-able.com" or event.dns.request contains ".n-able.com." or event.dns.request contains ".remote.management" or event.dns.request contains ".remote.management." or event.dns.request contains ".swi-tc.com" or event.dns.request contains ".swi-tc.com." or event.dns.request contains ".system-monitor.com" or event.dns.request contains ".system-monitor.com." or event.dns.request contains ".systemmonitor.co.uk" or event.dns.request contains ".systemmonitor.co.uk." or event.dns.request contains ".systemmonitor.eu.com" or event.dns.request contains ".systemmonitor.eu.com." or event.dns.request contains ".systemmonitor.us" or event.dns.request contains ".systemmonitor.us." or event.dns.request contains ".systemmonitor.us.cdn.cloudflare.net" or event.dns.request contains ".systemmonitor.us.cdn.cloudflare.net." or event.dns.request="beanywhere.com" or event.dns.request="beanywhere.com." or event.dns.request="cloudbackup.management" or event.dns.request="cloudbackup.management." or event.dns.request="logicnow.com" or event.dns.request="logicnow.com." or event.dns.request="n-able.com" or event.dns.request="n-able.com." or event.dns.request="remote.management" or event.dns.request="remote.management." or event.dns.request="system-monitor.com" or event.dns.request="system-monitor.com." or event.dns.request="systemmonitor.co.uk" or event.dns.request="systemmonitor.co.uk." or event.dns.request="systemmonitor.eu.com" or event.dns.request="systemmonitor.eu.com." or event.dns.request="systemmonitor.us" or event.dns.request="systemmonitor.us." or event.dns.request="systemmonitor.us.cdn.cloudflare.net" or event.dns.request="systemmonitor.us.cdn.cloudflare.net.")))
```


# Original Sigma Rule:
```yaml
title: Potential N-Able Advanced Monitoring Agent RMM Tool Network Activity
id: 343b65e8-9f87-4009-9649-fb77db5d1e7f
status: experimental
description: |
    Detects potential network activity of N-Able Advanced Monitoring Agent RMM tool
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
            - '*.beanywhere.com'
            - '*.beanywhere.com.'
            - '*.cloudbackup.management'
            - '*.cloudbackup.management.'
            - '*.logicnow.com'
            - '*.logicnow.com.'
            - '*.n-able.com'
            - '*.n-able.com.'
            - '*.remote.management'
            - '*.remote.management.'
            - '*.swi-tc.com'
            - '*.swi-tc.com.'
            - '*.system-monitor.com'
            - '*.system-monitor.com.'
            - '*.systemmonitor.co.uk'
            - '*.systemmonitor.co.uk.'
            - '*.systemmonitor.eu.com'
            - '*.systemmonitor.eu.com.'
            - '*.systemmonitor.us'
            - '*.systemmonitor.us.'
            - '*.systemmonitor.us.cdn.cloudflare.net'
            - '*.systemmonitor.us.cdn.cloudflare.net.'
            - 'beanywhere.com'
            - 'beanywhere.com.'
            - 'cloudbackup.management'
            - 'cloudbackup.management.'
            - 'logicnow.com'
            - 'logicnow.com.'
            - 'n-able.com'
            - 'n-able.com.'
            - 'remote.management'
            - 'remote.management.'
            - 'system-monitor.com'
            - 'system-monitor.com.'
            - 'systemmonitor.co.uk'
            - 'systemmonitor.co.uk.'
            - 'systemmonitor.eu.com'
            - 'systemmonitor.eu.com.'
            - 'systemmonitor.us'
            - 'systemmonitor.us.'
            - 'systemmonitor.us.cdn.cloudflare.net'
            - 'systemmonitor.us.cdn.cloudflare.net.'
    condition: selection
falsepositives:
    - Legitimate use of N-Able Advanced Monitoring Agent
level: medium
```
