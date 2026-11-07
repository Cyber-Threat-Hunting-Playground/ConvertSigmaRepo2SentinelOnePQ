```sql
// Translated content (automatically translated on 07-11-2026 05:39:54):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\QuarksPwDump.exe" or (tgt.process.cmdline contains " -dhl" or tgt.process.cmdline contains " --dump-hash-local" or tgt.process.cmdline contains " -dhdc" or tgt.process.cmdline contains " --dump-hash-domain-cached" or tgt.process.cmdline contains " --dump-bitlocker" or tgt.process.cmdline contains " -dhd " or tgt.process.cmdline contains " --dump-hash-domain " or tgt.process.cmdline contains "--ntds-file")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Quarks PwDump Execution
id: 0685b176-c816-4837-8e7b-1216f346636b
status: test
description: Detects usage of the Quarks PwDump tool via commandline arguments
references:
    - https://github.com/quarkslab/quarkspwdump
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-apt-iran-middle-east
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-05
modified: 2026-11-05
tags:
    - attack.credential-access
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\QuarksPwDump.exe'
    selection_cli:
        CommandLine|contains:
            - ' -dhl'
            - ' --dump-hash-local'
            - ' -dhdc'
            - ' --dump-hash-domain-cached'
            - ' --dump-bitlocker'
            - ' -dhd '
            - ' --dump-hash-domain '
            - '--ntds-file'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
```
