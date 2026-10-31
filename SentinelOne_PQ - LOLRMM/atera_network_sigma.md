```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".pubsub.atera.com" or url.address contains ".pubsub.atera.com." or url.address="pubsub.atera.com" or url.address="pubsub.atera.com." or url.address contains ".agentreporting.atera.com" or url.address contains ".agentreporting.atera.com." or url.address="agentreporting.atera.com" or url.address="agentreporting.atera.com." or url.address contains ".getalphacontrol.com" or url.address contains ".getalphacontrol.com." or url.address="getalphacontrol.com" or url.address="getalphacontrol.com." or url.address contains ".app.atera.com" or url.address contains ".app.atera.com." or url.address="app.atera.com" or url.address="app.atera.com." or url.address contains ".agenthb.atera.com" or url.address contains ".agenthb.atera.com." or url.address="agenthb.atera.com" or url.address="agenthb.atera.com." or url.address contains ".packagesstore.blob.core.windows.net" or url.address contains ".packagesstore.blob.core.windows.net." or url.address="packagesstore.blob.core.windows.net" or url.address="packagesstore.blob.core.windows.net." or url.address contains ".agent-api.atera.com" or url.address contains ".agent-api.atera.com." or url.address="agent-api.atera.com" or url.address="agent-api.atera.com." or url.address contains ".agentreportingstore.blob.core.windows.net" or url.address contains ".agentreportingstore.blob.core.windows.net." or url.address="agentreportingstore.blob.core.windows.net" or url.address="agentreportingstore.blob.core.windows.net." or url.address contains ".atera-agent-heartbeat.servicebus.windows.net" or url.address contains ".atera-agent-heartbeat.servicebus.windows.net." or url.address="atera-agent-heartbeat.servicebus.windows.net" or url.address="atera-agent-heartbeat.servicebus.windows.net." or url.address contains ".ps.atera.com" or url.address contains ".ps.atera.com." or url.address="ps.atera.com" or url.address="ps.atera.com." or url.address contains ".atera.pubnubapi.com" or url.address contains ".atera.pubnubapi.com." or url.address="atera.pubnubapi.com" or url.address="atera.pubnubapi.com." or url.address contains ".appcdn.atera.com" or url.address contains ".appcdn.atera.com." or url.address="appcdn.atera.com" or url.address="appcdn.atera.com.") or (event.dns.request contains ".pubsub.atera.com" or event.dns.request contains ".pubsub.atera.com." or event.dns.request="pubsub.atera.com" or event.dns.request="pubsub.atera.com." or event.dns.request contains ".agentreporting.atera.com" or event.dns.request contains ".agentreporting.atera.com." or event.dns.request="agentreporting.atera.com" or event.dns.request="agentreporting.atera.com." or event.dns.request contains ".getalphacontrol.com" or event.dns.request contains ".getalphacontrol.com." or event.dns.request="getalphacontrol.com" or event.dns.request="getalphacontrol.com." or event.dns.request contains ".app.atera.com" or event.dns.request contains ".app.atera.com." or event.dns.request="app.atera.com" or event.dns.request="app.atera.com." or event.dns.request contains ".agenthb.atera.com" or event.dns.request contains ".agenthb.atera.com." or event.dns.request="agenthb.atera.com" or event.dns.request="agenthb.atera.com." or event.dns.request contains ".packagesstore.blob.core.windows.net" or event.dns.request contains ".packagesstore.blob.core.windows.net." or event.dns.request="packagesstore.blob.core.windows.net" or event.dns.request="packagesstore.blob.core.windows.net." or event.dns.request contains ".agent-api.atera.com" or event.dns.request contains ".agent-api.atera.com." or event.dns.request="agent-api.atera.com" or event.dns.request="agent-api.atera.com." or event.dns.request contains ".agentreportingstore.blob.core.windows.net" or event.dns.request contains ".agentreportingstore.blob.core.windows.net." or event.dns.request="agentreportingstore.blob.core.windows.net" or event.dns.request="agentreportingstore.blob.core.windows.net." or event.dns.request contains ".atera-agent-heartbeat.servicebus.windows.net" or event.dns.request contains ".atera-agent-heartbeat.servicebus.windows.net." or event.dns.request="atera-agent-heartbeat.servicebus.windows.net" or event.dns.request="atera-agent-heartbeat.servicebus.windows.net." or event.dns.request contains ".ps.atera.com" or event.dns.request contains ".ps.atera.com." or event.dns.request="ps.atera.com" or event.dns.request="ps.atera.com." or event.dns.request contains ".atera.pubnubapi.com" or event.dns.request contains ".atera.pubnubapi.com." or event.dns.request="atera.pubnubapi.com" or event.dns.request="atera.pubnubapi.com." or event.dns.request contains ".appcdn.atera.com" or event.dns.request contains ".appcdn.atera.com." or event.dns.request="appcdn.atera.com" or event.dns.request="appcdn.atera.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Atera RMM Tool Network Activity
id: 674787f1-97f4-4b3f-ae3a-361e909e800d
status: experimental
description: |
    Detects potential network activity of Atera RMM tool
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
            - '*.pubsub.atera.com'
            - '*.pubsub.atera.com.'
            - 'pubsub.atera.com'
            - 'pubsub.atera.com.'
            - '*.agentreporting.atera.com'
            - '*.agentreporting.atera.com.'
            - 'agentreporting.atera.com'
            - 'agentreporting.atera.com.'
            - '*.getalphacontrol.com'
            - '*.getalphacontrol.com.'
            - 'getalphacontrol.com'
            - 'getalphacontrol.com.'
            - '*.app.atera.com'
            - '*.app.atera.com.'
            - 'app.atera.com'
            - 'app.atera.com.'
            - '*.agenthb.atera.com'
            - '*.agenthb.atera.com.'
            - 'agenthb.atera.com'
            - 'agenthb.atera.com.'
            - '*.packagesstore.blob.core.windows.net'
            - '*.packagesstore.blob.core.windows.net.'
            - 'packagesstore.blob.core.windows.net'
            - 'packagesstore.blob.core.windows.net.'
            - '*.agent-api.atera.com'
            - '*.agent-api.atera.com.'
            - 'agent-api.atera.com'
            - 'agent-api.atera.com.'
            - '*.agentreportingstore.blob.core.windows.net'
            - '*.agentreportingstore.blob.core.windows.net.'
            - 'agentreportingstore.blob.core.windows.net'
            - 'agentreportingstore.blob.core.windows.net.'
            - '*.atera-agent-heartbeat.servicebus.windows.net'
            - '*.atera-agent-heartbeat.servicebus.windows.net.'
            - 'atera-agent-heartbeat.servicebus.windows.net'
            - 'atera-agent-heartbeat.servicebus.windows.net.'
            - '*.ps.atera.com'
            - '*.ps.atera.com.'
            - 'ps.atera.com'
            - 'ps.atera.com.'
            - '*.atera.pubnubapi.com'
            - '*.atera.pubnubapi.com.'
            - 'atera.pubnubapi.com'
            - 'atera.pubnubapi.com.'
            - '*.appcdn.atera.com'
            - '*.appcdn.atera.com.'
            - 'appcdn.atera.com'
            - 'appcdn.atera.com.'
    condition: selection
falsepositives:
    - Legitimate use of Atera
level: medium
```
