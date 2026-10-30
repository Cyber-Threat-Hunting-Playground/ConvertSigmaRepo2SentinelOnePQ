```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".sis.n-able.com" or url.address contains ".sis.n-able.com." or url.address="sis.n-able.com" or url.address="sis.n-able.com." or url.address contains ".feeds.n-able.com" or url.address contains ".feeds.n-able.com." or url.address contains ".releases.n-able.com" or url.address contains ".releases.n-able.com." or url.address contains ".update.n-able.com" or url.address contains ".update.n-able.com." or url.address="feeds.n-able.com" or url.address="feeds.n-able.com." or url.address="releases.n-able.com" or url.address="releases.n-able.com." or url.address="update.n-able.com" or url.address="update.n-able.com." or url.address contains ".eb.ap-southeast-2.prd.davinci.system-monitor.com" or url.address contains ".eb.ap-southeast-2.prd.davinci.system-monitor.com." or url.address contains ".eb.eu-central-1.prd.davinci.system-monitor.com" or url.address contains ".eb.eu-central-1.prd.davinci.system-monitor.com." or url.address contains ".eb.eu-west-1.prd.davinci.system-monitor.com" or url.address contains ".eb.eu-west-1.prd.davinci.system-monitor.com." or url.address contains ".eb.us-west-2.prd.davinci.system-monitor.com" or url.address contains ".eb.us-west-2.prd.davinci.system-monitor.com." or url.address contains ".prd.cdo.system-monitor.com" or url.address contains ".prd.cdo.system-monitor.com." or url.address="eb.ap-southeast-2.prd.davinci.system-monitor.com" or url.address="eb.ap-southeast-2.prd.davinci.system-monitor.com." or url.address="eb.eu-central-1.prd.davinci.system-monitor.com" or url.address="eb.eu-central-1.prd.davinci.system-monitor.com." or url.address="eb.eu-west-1.prd.davinci.system-monitor.com" or url.address="eb.eu-west-1.prd.davinci.system-monitor.com." or url.address="eb.us-west-2.prd.davinci.system-monitor.com" or url.address="eb.us-west-2.prd.davinci.system-monitor.com." or url.address contains ".a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com" or url.address contains ".a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com." or url.address contains ".a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com" or url.address contains ".a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com." or url.address contains ".a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com" or url.address contains ".a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com." or url.address contains ".a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com" or url.address contains ".a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com." or url.address="a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com" or url.address="a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com." or url.address="a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com" or url.address="a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com." or url.address="a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com" or url.address="a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com." or url.address="a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com" or url.address="a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com." or url.address contains ".comserver.eu1.mspa.n-able.com" or url.address contains ".comserver.eu1.mspa.n-able.com." or url.address contains ".comserver.global.mspa.n-able.com" or url.address contains ".comserver.global.mspa.n-able.com." or url.address contains ".comserver.us1.mspa.n-able.com" or url.address contains ".comserver.us1.mspa.n-able.com." or url.address contains ".comserver.us2.mspa.n-able.com" or url.address contains ".comserver.us2.mspa.n-able.com." or url.address contains ".swi-rc.cdn-sw.net" or url.address contains ".swi-rc.cdn-sw.net." or url.address="comserver.eu1.mspa.n-able.com" or url.address="comserver.eu1.mspa.n-able.com." or url.address="comserver.global.mspa.n-able.com" or url.address="comserver.global.mspa.n-able.com." or url.address="comserver.us1.mspa.n-able.com" or url.address="comserver.us1.mspa.n-able.com." or url.address="comserver.us2.mspa.n-able.com" or url.address="comserver.us2.mspa.n-able.com." or url.address="swi-rc.cdn-sw.net" or url.address="swi-rc.cdn-sw.net.") or (event.dns.request contains ".sis.n-able.com" or event.dns.request contains ".sis.n-able.com." or event.dns.request="sis.n-able.com" or event.dns.request="sis.n-able.com." or event.dns.request contains ".feeds.n-able.com" or event.dns.request contains ".feeds.n-able.com." or event.dns.request contains ".releases.n-able.com" or event.dns.request contains ".releases.n-able.com." or event.dns.request contains ".update.n-able.com" or event.dns.request contains ".update.n-able.com." or event.dns.request="feeds.n-able.com" or event.dns.request="feeds.n-able.com." or event.dns.request="releases.n-able.com" or event.dns.request="releases.n-able.com." or event.dns.request="update.n-able.com" or event.dns.request="update.n-able.com." or event.dns.request contains ".eb.ap-southeast-2.prd.davinci.system-monitor.com" or event.dns.request contains ".eb.ap-southeast-2.prd.davinci.system-monitor.com." or event.dns.request contains ".eb.eu-central-1.prd.davinci.system-monitor.com" or event.dns.request contains ".eb.eu-central-1.prd.davinci.system-monitor.com." or event.dns.request contains ".eb.eu-west-1.prd.davinci.system-monitor.com" or event.dns.request contains ".eb.eu-west-1.prd.davinci.system-monitor.com." or event.dns.request contains ".eb.us-west-2.prd.davinci.system-monitor.com" or event.dns.request contains ".eb.us-west-2.prd.davinci.system-monitor.com." or event.dns.request contains ".prd.cdo.system-monitor.com" or event.dns.request contains ".prd.cdo.system-monitor.com." or event.dns.request="eb.ap-southeast-2.prd.davinci.system-monitor.com" or event.dns.request="eb.ap-southeast-2.prd.davinci.system-monitor.com." or event.dns.request="eb.eu-central-1.prd.davinci.system-monitor.com" or event.dns.request="eb.eu-central-1.prd.davinci.system-monitor.com." or event.dns.request="eb.eu-west-1.prd.davinci.system-monitor.com" or event.dns.request="eb.eu-west-1.prd.davinci.system-monitor.com." or event.dns.request="eb.us-west-2.prd.davinci.system-monitor.com" or event.dns.request="eb.us-west-2.prd.davinci.system-monitor.com." or event.dns.request contains ".a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com" or event.dns.request contains ".a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com." or event.dns.request contains ".a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com" or event.dns.request contains ".a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com." or event.dns.request contains ".a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com" or event.dns.request contains ".a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com." or event.dns.request contains ".a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com" or event.dns.request contains ".a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com." or event.dns.request="a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com" or event.dns.request="a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com." or event.dns.request="a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com" or event.dns.request="a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com." or event.dns.request="a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com" or event.dns.request="a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com." or event.dns.request="a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com" or event.dns.request="a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com." or event.dns.request contains ".comserver.eu1.mspa.n-able.com" or event.dns.request contains ".comserver.eu1.mspa.n-able.com." or event.dns.request contains ".comserver.global.mspa.n-able.com" or event.dns.request contains ".comserver.global.mspa.n-able.com." or event.dns.request contains ".comserver.us1.mspa.n-able.com" or event.dns.request contains ".comserver.us1.mspa.n-able.com." or event.dns.request contains ".comserver.us2.mspa.n-able.com" or event.dns.request contains ".comserver.us2.mspa.n-able.com." or event.dns.request contains ".swi-rc.cdn-sw.net" or event.dns.request contains ".swi-rc.cdn-sw.net." or event.dns.request="comserver.eu1.mspa.n-able.com" or event.dns.request="comserver.eu1.mspa.n-able.com." or event.dns.request="comserver.global.mspa.n-able.com" or event.dns.request="comserver.global.mspa.n-able.com." or event.dns.request="comserver.us1.mspa.n-able.com" or event.dns.request="comserver.us1.mspa.n-able.com." or event.dns.request="comserver.us2.mspa.n-able.com" or event.dns.request="comserver.us2.mspa.n-able.com." or event.dns.request="swi-rc.cdn-sw.net" or event.dns.request="swi-rc.cdn-sw.net.")))
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
            - '*.sis.n-able.com'
            - '*.sis.n-able.com.'
            - 'sis.n-able.com'
            - 'sis.n-able.com.'
            - '*.feeds.n-able.com'
            - '*.feeds.n-able.com.'
            - '*.releases.n-able.com'
            - '*.releases.n-able.com.'
            - '*.update.n-able.com'
            - '*.update.n-able.com.'
            - 'feeds.n-able.com'
            - 'feeds.n-able.com.'
            - 'releases.n-able.com'
            - 'releases.n-able.com.'
            - 'update.n-able.com'
            - 'update.n-able.com.'
            - '*.eb.ap-southeast-2.prd.davinci.system-monitor.com'
            - '*.eb.ap-southeast-2.prd.davinci.system-monitor.com.'
            - '*.eb.eu-central-1.prd.davinci.system-monitor.com'
            - '*.eb.eu-central-1.prd.davinci.system-monitor.com.'
            - '*.eb.eu-west-1.prd.davinci.system-monitor.com'
            - '*.eb.eu-west-1.prd.davinci.system-monitor.com.'
            - '*.eb.us-west-2.prd.davinci.system-monitor.com'
            - '*.eb.us-west-2.prd.davinci.system-monitor.com.'
            - '*.prd.cdo.system-monitor.com'
            - '*.prd.cdo.system-monitor.com.'
            - 'eb.ap-southeast-2.prd.davinci.system-monitor.com'
            - 'eb.ap-southeast-2.prd.davinci.system-monitor.com.'
            - 'eb.eu-central-1.prd.davinci.system-monitor.com'
            - 'eb.eu-central-1.prd.davinci.system-monitor.com.'
            - 'eb.eu-west-1.prd.davinci.system-monitor.com'
            - 'eb.eu-west-1.prd.davinci.system-monitor.com.'
            - 'eb.us-west-2.prd.davinci.system-monitor.com'
            - 'eb.us-west-2.prd.davinci.system-monitor.com.'
            - '*.a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com'
            - '*.a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com.'
            - '*.a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com'
            - '*.a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com.'
            - '*.a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com'
            - '*.a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com.'
            - '*.a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com'
            - '*.a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com.'
            - 'a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com'
            - 'a33d8yamkwy4nx-ats.iot.ap-southeast-2.amazonaws.com.'
            - 'a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com'
            - 'a33d8yamkwy4nx-ats.iot.eu-central-1.amazonaws.com.'
            - 'a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com'
            - 'a33d8yamkwy4nx-ats.iot.eu-west-1.amazonaws.com.'
            - 'a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com'
            - 'a33d8yamkwy4nx-ats.iot.us-west-2.amazonaws.com.'
            - '*.comserver.eu1.mspa.n-able.com'
            - '*.comserver.eu1.mspa.n-able.com.'
            - '*.comserver.global.mspa.n-able.com'
            - '*.comserver.global.mspa.n-able.com.'
            - '*.comserver.us1.mspa.n-able.com'
            - '*.comserver.us1.mspa.n-able.com.'
            - '*.comserver.us2.mspa.n-able.com'
            - '*.comserver.us2.mspa.n-able.com.'
            - '*.swi-rc.cdn-sw.net'
            - '*.swi-rc.cdn-sw.net.'
            - 'comserver.eu1.mspa.n-able.com'
            - 'comserver.eu1.mspa.n-able.com.'
            - 'comserver.global.mspa.n-able.com'
            - 'comserver.global.mspa.n-able.com.'
            - 'comserver.us1.mspa.n-able.com'
            - 'comserver.us1.mspa.n-able.com.'
            - 'comserver.us2.mspa.n-able.com'
            - 'comserver.us2.mspa.n-able.com.'
            - 'swi-rc.cdn-sw.net'
            - 'swi-rc.cdn-sw.net.'
    condition: selection
falsepositives:
    - Legitimate use of N-able N-central
level: medium
```
