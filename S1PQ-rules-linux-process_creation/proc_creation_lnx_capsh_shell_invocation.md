```sql
// Translated content (automatically translated on 10-11-2026 05:13:54):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/capsh" and tgt.process.cmdline contains " --"))
```


# Original Sigma Rule:
```yaml
title: Capsh Shell Invocation - Linux
id: db1ac3be-f606-4e3a-89e0-9607cbe6b98a
status: test
description: |
    Detects the use of the "capsh" utility to invoke a shell.
references:
    - https://gtfobins.github.io/gtfobins/capsh/#shell
    - https://github.com/elastic/detection-rules/blob/0aacc5e19292f764a002ea2093b2a076db35b589/rules/_deprecated/execution_shell_evasion_linux_binary.toml
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/capsh'
        CommandLine|endswith: ' --'
    condition: selection
falsepositives:
    - Unknown
level: high
```
