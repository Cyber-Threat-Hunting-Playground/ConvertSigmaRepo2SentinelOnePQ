```sql
// Translated content (automatically translated on 10-10-2026 03:12:59):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "sis.n-able.com" or url.address contains "update.n-able.com" or url.address contains "releases.n-able.com" or url.address contains "feeds.n-able.com" or url.address contains ".prd.cdo.system-monitor.com" or url.address contains "eb.eu-west-1.prd.davinci.system-monitor.com" or url.address contains "eb.us-west-2.prd.davinci.system-monitor.com" or url.address contains "eb.ap-southeast-2.prd.davinci.system-monitor.com" or url.address contains "eb.eu-central-1.prd.davinci.system-monitor.com" or url.address contains "a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com" or url.address contains "a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com" or url.address contains "a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com" or url.address contains "a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com" or url.address contains "swi-rc.cdn-sw.net" or url.address contains "comserver.global.mspa.n-able.com" or url.address contains "comserver.us1.mspa.n-able.com" or url.address contains "comserver.us2.mspa.n-able.com" or url.address contains "comserver.eu1.mspa.n-able.com") or (event.dns.request contains "sis.n-able.com" or event.dns.request contains "update.n-able.com" or event.dns.request contains "releases.n-able.com" or event.dns.request contains "feeds.n-able.com" or event.dns.request contains ".prd.cdo.system-monitor.com" or event.dns.request contains "eb.eu-west-1.prd.davinci.system-monitor.com" or event.dns.request contains "eb.us-west-2.prd.davinci.system-monitor.com" or event.dns.request contains "eb.ap-southeast-2.prd.davinci.system-monitor.com" or event.dns.request contains "eb.eu-central-1.prd.davinci.system-monitor.com" or event.dns.request contains "a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com" or event.dns.request contains "a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com" or event.dns.request contains "a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com" or event.dns.request contains "a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com" or event.dns.request contains "swi-rc.cdn-sw.net" or event.dns.request contains "comserver.global.mspa.n-able.com" or event.dns.request contains "comserver.us1.mspa.n-able.com" or event.dns.request contains "comserver.us2.mspa.n-able.com" or event.dns.request contains "comserver.eu1.mspa.n-able.com")))
```


# Original Sigma Rule:
```yaml
title: Potential N-able N-central RMM Tool Network Activity
id: daf5482d-80e9-5951-8a70-22bb7ef1ee04
status: experimental
description: |
    Detects potential network activity of N-able N-central RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'sis.n-able.com'
            - 'update.n-able.com'
            - 'releases.n-able.com'
            - 'feeds.n-able.com'
            - '*.prd.cdo.system-monitor.com'
            - 'eb.eu-west-1.prd.davinci.system-monitor.com'
            - 'eb.us-west-2.prd.davinci.system-monitor.com'
            - 'eb.ap-southeast-2.prd.davinci.system-monitor.com'
            - 'eb.eu-central-1.prd.davinci.system-monitor.com'
            - 'a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com'
            - 'a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com'
            - 'a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com'
            - 'a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com'
            - 'swi-rc.cdn-sw.net'
            - 'comserver.global.mspa.n-able.com'
            - 'comserver.us1.mspa.n-able.com'
            - 'comserver.us2.mspa.n-able.com'
            - 'comserver.eu1.mspa.n-able.com'
    condition: selection
falsepositives:
    - Legitimate use of N-able N-central
level: medium
```
