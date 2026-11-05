```sql
// Translated content (automatically translated on 05-11-2026 06:13:50):
event.category="dns" and (endpoint.os="windows" and (event.dns.request contains ".1u.ms" or event.dns.request contains ".backname.io" or event.dns.request contains ".nip.io" or event.dns.request contains ".sslip.io" or event.dns.request contains ".traefik.me" or event.dns.request contains ".xip.io"))
```


# Original Sigma Rule:
```yaml
title: DNS Query to Wildcard DNS Services - Windows
id: 4f8a1c2e-7d3b-4e5f-9a6c-0b1d2e3f4a5b
related:
    - id: 139ddcb3-ba90-4407-b0b1-1838131ce8e7
      type: similar
status: experimental
description: |
    Detects DNS queries to public wildcard DNS services that dynamically resolve subdomains to IP addresses embedded in the subdomain.
    Adversaries abuse these services to establish C2 channels or stage phishing infrastructure without registering a custom domain, potentially to evade detection and attribution.
references:
    - https://nip.io/
    - https://sslip.io/
    - https://traefik.me/
    - https://github.polettix.it/ETOOBUSY/2022/10/09/nip-io-sslip-io/
author: MahirAli Khan, Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2026-11-05
tags:
    - attack.command-and-control
    - attack.t1071.004
    - attack.t1568
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            # IP-embedding services (subdomain encodes an arbitrary IP)
            - '.1u.ms'
            - '.backname.io'
            - '.nip.io'
            - '.sslip.io'
            - '.traefik.me'
            - '.xip.io'
    condition: selection
falsepositives:
    - Developers on Windows workstations testing local services or web applications without editing the hosts file
level: medium
regression_tests_path: regression_data/rules/windows/dns_query/dns_query_win_wildcard_dns_service/info.yml
```
