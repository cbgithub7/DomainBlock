# Contributing

## Layout

| Path | Role |
| --- | --- |
| `DomainBlock/` | PowerShell module (public cmdlets in `Public/`, helpers in `Private/`) |
| `examples/` | Sample domain lists |
| `tests/` | Self-tests |

Public files are named after the function they define (`Block-Domain.ps1` exports `Block-Domain`). Use approved PowerShell verbs and PascalCase for identifiers. Three-letter acronyms use Pascal case (`Mac`, not `MAC`).

## Tests

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-DomainBlockTest.ps1
```

Hosts-file tests use a temp file and do not need elevation. Pass `-LiveFirewall` in an elevated session to include firewall checks. The same script runs on `push` and `pull_request` via `.github/workflows/test.yml`.

Do not commit credentials, tokens, or hosts-file backups.
