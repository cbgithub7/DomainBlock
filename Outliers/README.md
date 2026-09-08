# Outliers

These scripts are **not** part of the DomainBlock module. They are leftover utilities from the original collection.

| Script | Purpose |
| --- | --- |
| `Remove-LockedFile.ps1` | Find locking processes (Restart Manager), optionally stop them, recycle or delete the file |
| `Get-DeviceMacInfo.ps1` | Neighbor IP/MAC inventory from `Get-NetNeighbor` (ARP fallback), optional vendor lookup |
| `Invoke-NetworkDiagnostics.ps1` | Ping, DNS, and traceroute for one host |

They are independent `.ps1` files with parameters, comment-based help, and no dependency on `DomainBlock`.

```powershell
.\Outliers\Invoke-NetworkDiagnostics.ps1 -ComputerName example.com -SkipTraceRoute
.\Outliers\Get-DeviceMacInfo.ps1
Get-Help .\Outliers\Remove-LockedFile.ps1 -Full
```
