# DomainBlock

Windows PowerShell toolkit for blocking and inspecting domains via the hosts file and Windows Firewall.

Requires Windows PowerShell 5.1 or PowerShell 7 on Windows. Changing the system hosts file or firewall rules needs an elevated session.

```powershell
Import-Module .\DomainBlock

Invoke-DomainBlockWorkflow -Action Apply -Name ads.example.com -Method Hosts
Get-BlockedDomain
Invoke-DomainBlockWorkflow -Action Remove -Name ads.example.com -Method Hosts
```

Hosts entries look like:

```
127.0.0.1 ads.example.com # DomainBlock
::1 ads.example.com # DomainBlock
```

Firewall rules are named per domain and IP, grouped as `DomainBlock`. Re-running `Block-Domain` does not create duplicates.

Firewall IP blocks go stale when CDNs rotate addresses. Refresh them with `Update-DomainFirewallBlock`. Hosts-file blocks can be bypassed by DNS-over-HTTPS, VPNs, or apps that ignore the system resolver.

### Commands

| Command | Purpose |
| --- | --- |
| `Block-Domain` | Block via hosts, firewall, or both |
| `Unblock-Domain` | Remove toolkit-managed blocks |
| `Get-BlockedDomain` | List what this module created |
| `Test-DomainBlock` | Hosts + firewall + loopback DNS view |
| `Update-DomainFirewallBlock` | Re-resolve DNS and sync firewall IPs |
| `Find-FirewallDomainRule` | Search *any* firewall rule covering a domain's IPs |
| `Get-DomainIPAddress` | Resolve A/AAAA addresses |
| `ConvertTo-DomainListLiteral` | Column of names → `@("a", "b")` |
| `Backup-HostsFile` / `Restore-HostsFile` | Timestamped hosts backups under `Documents\DomainBlock` |
| `Export-BlockedDomain` / `Import-BlockedDomain` | Text or JSON domain lists |
| `Invoke-DomainBlockWorkflow` | Run Apply, Refresh, or Remove as a sequence |

```powershell
Get-Help about_DomainBlock
Get-Command -Module DomainBlock
Get-Help Block-Domain -Examples
```

### Sequences

Running every command in order is not useful: `Block-Domain` and `Unblock-Domain` cancel each other, and `Restore-HostsFile` undoes a backup.

The sequences that *are* worth chaining, each step waiting for the previous to finish:

| Action | Steps |
| --- | --- |
| Apply | `Backup-HostsFile` → `Block-Domain` → `Test-DomainBlock` |
| Refresh | `Update-DomainFirewallBlock` → `Test-DomainBlock` |
| Remove | `Backup-HostsFile` → `Unblock-Domain` → `Test-DomainBlock` |

```powershell
Invoke-DomainBlockWorkflow -Action Apply -Path .\examples\DomainList.txt -Method Hosts
Invoke-DomainBlockWorkflow -Action Refresh
Invoke-DomainBlockWorkflow -Action Remove -Name ads.example.com
```

Use the individual commands when you need a single step (`Get-BlockedDomain`, `Find-FirewallDomainRule`, export/import, restore).

### Lists

`examples/DomainList.txt` is a commented template. One domain per line; `#` comments are ignored. JSON from `Export-BlockedDomain` is also accepted.

```powershell
Block-Domain -Path .\examples\DomainList.txt -Method Hosts -WhatIf
Get-Content .\list.txt | ConvertTo-DomainListLiteral
```

## Tests

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-DomainBlockTest.ps1
```

Hosts-file tests use a temp file and do not require elevation. Firewall live tests are skipped unless you pass `-LiveFirewall` in an elevated session.

## License

MIT. See [LICENSE](LICENSE).
