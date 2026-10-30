```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".vicarius-ap-southeast-3-installer.s3.amazonaws.com" or url.address contains ".vicarius-ap-southeast-3-installer.s3.amazonaws.com." or url.address contains ".vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com" or url.address contains ".vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com." or url.address contains ".vicarius-ap-southeast-3-patches.s3.amazonaws.com" or url.address contains ".vicarius-ap-southeast-3-patches.s3.amazonaws.com." or url.address contains ".vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com" or url.address contains ".vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com." or url.address contains ".vicarius-ap-southeast-3-release.s3.amazonaws.com" or url.address contains ".vicarius-ap-southeast-3-release.s3.amazonaws.com." or url.address contains ".vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com" or url.address contains ".vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com." or url.address contains ".vicarius-eu-central-1-installer.s3.amazonaws.com" or url.address contains ".vicarius-eu-central-1-installer.s3.amazonaws.com." or url.address contains ".vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com" or url.address contains ".vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com." or url.address contains ".vicarius-eu-central-1-patches.s3.amazonaws.com" or url.address contains ".vicarius-eu-central-1-patches.s3.amazonaws.com." or url.address contains ".vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com" or url.address contains ".vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com." or url.address contains ".vicarius-eu-central-1-release.s3.amazonaws.com" or url.address contains ".vicarius-eu-central-1-release.s3.amazonaws.com." or url.address contains ".vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com" or url.address contains ".vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com." or url.address contains ".vicarius-installer.s3.amazonaws.com" or url.address contains ".vicarius-installer.s3.amazonaws.com." or url.address contains ".vicarius-patches.s3.amazonaws.com" or url.address contains ".vicarius-patches.s3.amazonaws.com." or url.address contains ".vicarius-release.s3.amazonaws.com" or url.address contains ".vicarius-release.s3.amazonaws.com." or url.address contains ".vicarius-release.s3.us-east-1.amazonaws.com" or url.address contains ".vicarius-release.s3.us-east-1.amazonaws.com." or url.address contains ".vicarius-static-organizationinstallations.vicarius-cdn.com" or url.address contains ".vicarius-static-organizationinstallations.vicarius-cdn.com." or url.address contains ".vicarius.cloud" or url.address contains ".vicarius.cloud." or url.address="vicarius-ap-southeast-3-installer.s3.amazonaws.com" or url.address="vicarius-ap-southeast-3-installer.s3.amazonaws.com." or url.address="vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com" or url.address="vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com." or url.address="vicarius-ap-southeast-3-patches.s3.amazonaws.com" or url.address="vicarius-ap-southeast-3-patches.s3.amazonaws.com." or url.address="vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com" or url.address="vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com." or url.address="vicarius-ap-southeast-3-release.s3.amazonaws.com" or url.address="vicarius-ap-southeast-3-release.s3.amazonaws.com." or url.address="vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com" or url.address="vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com." or url.address="vicarius-eu-central-1-installer.s3.amazonaws.com" or url.address="vicarius-eu-central-1-installer.s3.amazonaws.com." or url.address="vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com" or url.address="vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com." or url.address="vicarius-eu-central-1-patches.s3.amazonaws.com" or url.address="vicarius-eu-central-1-patches.s3.amazonaws.com." or url.address="vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com" or url.address="vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com." or url.address="vicarius-eu-central-1-release.s3.amazonaws.com" or url.address="vicarius-eu-central-1-release.s3.amazonaws.com." or url.address="vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com" or url.address="vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com." or url.address="vicarius-installer.s3.amazonaws.com" or url.address="vicarius-installer.s3.amazonaws.com." or url.address="vicarius-patches.s3.amazonaws.com" or url.address="vicarius-patches.s3.amazonaws.com." or url.address="vicarius-release.s3.amazonaws.com" or url.address="vicarius-release.s3.amazonaws.com." or url.address="vicarius-release.s3.us-east-1.amazonaws.com" or url.address="vicarius-release.s3.us-east-1.amazonaws.com." or url.address="vicarius-static-organizationinstallations.vicarius-cdn.com" or url.address="vicarius-static-organizationinstallations.vicarius-cdn.com.") or (event.dns.request contains ".vicarius-ap-southeast-3-installer.s3.amazonaws.com" or event.dns.request contains ".vicarius-ap-southeast-3-installer.s3.amazonaws.com." or event.dns.request contains ".vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com" or event.dns.request contains ".vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com." or event.dns.request contains ".vicarius-ap-southeast-3-patches.s3.amazonaws.com" or event.dns.request contains ".vicarius-ap-southeast-3-patches.s3.amazonaws.com." or event.dns.request contains ".vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com" or event.dns.request contains ".vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com." or event.dns.request contains ".vicarius-ap-southeast-3-release.s3.amazonaws.com" or event.dns.request contains ".vicarius-ap-southeast-3-release.s3.amazonaws.com." or event.dns.request contains ".vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com" or event.dns.request contains ".vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com." or event.dns.request contains ".vicarius-eu-central-1-installer.s3.amazonaws.com" or event.dns.request contains ".vicarius-eu-central-1-installer.s3.amazonaws.com." or event.dns.request contains ".vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com" or event.dns.request contains ".vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com." or event.dns.request contains ".vicarius-eu-central-1-patches.s3.amazonaws.com" or event.dns.request contains ".vicarius-eu-central-1-patches.s3.amazonaws.com." or event.dns.request contains ".vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com" or event.dns.request contains ".vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com." or event.dns.request contains ".vicarius-eu-central-1-release.s3.amazonaws.com" or event.dns.request contains ".vicarius-eu-central-1-release.s3.amazonaws.com." or event.dns.request contains ".vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com" or event.dns.request contains ".vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com." or event.dns.request contains ".vicarius-installer.s3.amazonaws.com" or event.dns.request contains ".vicarius-installer.s3.amazonaws.com." or event.dns.request contains ".vicarius-patches.s3.amazonaws.com" or event.dns.request contains ".vicarius-patches.s3.amazonaws.com." or event.dns.request contains ".vicarius-release.s3.amazonaws.com" or event.dns.request contains ".vicarius-release.s3.amazonaws.com." or event.dns.request contains ".vicarius-release.s3.us-east-1.amazonaws.com" or event.dns.request contains ".vicarius-release.s3.us-east-1.amazonaws.com." or event.dns.request contains ".vicarius-static-organizationinstallations.vicarius-cdn.com" or event.dns.request contains ".vicarius-static-organizationinstallations.vicarius-cdn.com." or event.dns.request contains ".vicarius.cloud" or event.dns.request contains ".vicarius.cloud." or event.dns.request="vicarius-ap-southeast-3-installer.s3.amazonaws.com" or event.dns.request="vicarius-ap-southeast-3-installer.s3.amazonaws.com." or event.dns.request="vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com" or event.dns.request="vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com." or event.dns.request="vicarius-ap-southeast-3-patches.s3.amazonaws.com" or event.dns.request="vicarius-ap-southeast-3-patches.s3.amazonaws.com." or event.dns.request="vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com" or event.dns.request="vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com." or event.dns.request="vicarius-ap-southeast-3-release.s3.amazonaws.com" or event.dns.request="vicarius-ap-southeast-3-release.s3.amazonaws.com." or event.dns.request="vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com" or event.dns.request="vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com." or event.dns.request="vicarius-eu-central-1-installer.s3.amazonaws.com" or event.dns.request="vicarius-eu-central-1-installer.s3.amazonaws.com." or event.dns.request="vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com" or event.dns.request="vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com." or event.dns.request="vicarius-eu-central-1-patches.s3.amazonaws.com" or event.dns.request="vicarius-eu-central-1-patches.s3.amazonaws.com." or event.dns.request="vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com" or event.dns.request="vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com." or event.dns.request="vicarius-eu-central-1-release.s3.amazonaws.com" or event.dns.request="vicarius-eu-central-1-release.s3.amazonaws.com." or event.dns.request="vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com" or event.dns.request="vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com." or event.dns.request="vicarius-installer.s3.amazonaws.com" or event.dns.request="vicarius-installer.s3.amazonaws.com." or event.dns.request="vicarius-patches.s3.amazonaws.com" or event.dns.request="vicarius-patches.s3.amazonaws.com." or event.dns.request="vicarius-release.s3.amazonaws.com" or event.dns.request="vicarius-release.s3.amazonaws.com." or event.dns.request="vicarius-release.s3.us-east-1.amazonaws.com" or event.dns.request="vicarius-release.s3.us-east-1.amazonaws.com." or event.dns.request="vicarius-static-organizationinstallations.vicarius-cdn.com" or event.dns.request="vicarius-static-organizationinstallations.vicarius-cdn.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Vicarius vRx RMM Tool Network Activity
id: 38d3cc1d-15e3-551c-9f75-5ee204032e4b
status: experimental
description: |
    Detects potential network activity of Vicarius vRx RMM tool
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
            - '*.vicarius-ap-southeast-3-installer.s3.amazonaws.com'
            - '*.vicarius-ap-southeast-3-installer.s3.amazonaws.com.'
            - '*.vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com'
            - '*.vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com.'
            - '*.vicarius-ap-southeast-3-patches.s3.amazonaws.com'
            - '*.vicarius-ap-southeast-3-patches.s3.amazonaws.com.'
            - '*.vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com'
            - '*.vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com.'
            - '*.vicarius-ap-southeast-3-release.s3.amazonaws.com'
            - '*.vicarius-ap-southeast-3-release.s3.amazonaws.com.'
            - '*.vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com'
            - '*.vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com.'
            - '*.vicarius-eu-central-1-installer.s3.amazonaws.com'
            - '*.vicarius-eu-central-1-installer.s3.amazonaws.com.'
            - '*.vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com'
            - '*.vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com.'
            - '*.vicarius-eu-central-1-patches.s3.amazonaws.com'
            - '*.vicarius-eu-central-1-patches.s3.amazonaws.com.'
            - '*.vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com'
            - '*.vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com.'
            - '*.vicarius-eu-central-1-release.s3.amazonaws.com'
            - '*.vicarius-eu-central-1-release.s3.amazonaws.com.'
            - '*.vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com'
            - '*.vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com.'
            - '*.vicarius-installer.s3.amazonaws.com'
            - '*.vicarius-installer.s3.amazonaws.com.'
            - '*.vicarius-patches.s3.amazonaws.com'
            - '*.vicarius-patches.s3.amazonaws.com.'
            - '*.vicarius-release.s3.amazonaws.com'
            - '*.vicarius-release.s3.amazonaws.com.'
            - '*.vicarius-release.s3.us-east-1.amazonaws.com'
            - '*.vicarius-release.s3.us-east-1.amazonaws.com.'
            - '*.vicarius-static-organizationinstallations.vicarius-cdn.com'
            - '*.vicarius-static-organizationinstallations.vicarius-cdn.com.'
            - '*.vicarius.cloud'
            - '*.vicarius.cloud.'
            - 'vicarius-ap-southeast-3-installer.s3.amazonaws.com'
            - 'vicarius-ap-southeast-3-installer.s3.amazonaws.com.'
            - 'vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com'
            - 'vicarius-ap-southeast-3-installer.s3.ap-southeast-3.amazonaws.com.'
            - 'vicarius-ap-southeast-3-patches.s3.amazonaws.com'
            - 'vicarius-ap-southeast-3-patches.s3.amazonaws.com.'
            - 'vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com'
            - 'vicarius-ap-southeast-3-patches.s3.ap-southeast-3.amazonaws.com.'
            - 'vicarius-ap-southeast-3-release.s3.amazonaws.com'
            - 'vicarius-ap-southeast-3-release.s3.amazonaws.com.'
            - 'vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com'
            - 'vicarius-ap-southeast-3-release.s3.ap-southeast-3.amazonaws.com.'
            - 'vicarius-eu-central-1-installer.s3.amazonaws.com'
            - 'vicarius-eu-central-1-installer.s3.amazonaws.com.'
            - 'vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com'
            - 'vicarius-eu-central-1-installer.s3.eu-central-1.amazonaws.com.'
            - 'vicarius-eu-central-1-patches.s3.amazonaws.com'
            - 'vicarius-eu-central-1-patches.s3.amazonaws.com.'
            - 'vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com'
            - 'vicarius-eu-central-1-patches.s3.eu-central-1.amazonaws.com.'
            - 'vicarius-eu-central-1-release.s3.amazonaws.com'
            - 'vicarius-eu-central-1-release.s3.amazonaws.com.'
            - 'vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com'
            - 'vicarius-eu-central-1-release.s3.eu-central-1.amazonaws.com.'
            - 'vicarius-installer.s3.amazonaws.com'
            - 'vicarius-installer.s3.amazonaws.com.'
            - 'vicarius-patches.s3.amazonaws.com'
            - 'vicarius-patches.s3.amazonaws.com.'
            - 'vicarius-release.s3.amazonaws.com'
            - 'vicarius-release.s3.amazonaws.com.'
            - 'vicarius-release.s3.us-east-1.amazonaws.com'
            - 'vicarius-release.s3.us-east-1.amazonaws.com.'
            - 'vicarius-static-organizationinstallations.vicarius-cdn.com'
            - 'vicarius-static-organizationinstallations.vicarius-cdn.com.'
    condition: selection
falsepositives:
    - Legitimate use of Vicarius vRx
level: medium
```
