# Changelog

## 1.0.1 - 2026-09-08

- Keep local-only utilities out of the public tree.
- Public README covers DomainBlock only.
- Repository renamed from PowerScripts-Assorted-Utilities to DomainBlock.

## 1.0.0 - 2026-09-08

First DomainBlock toolkit release.

- Replace one-off root scripts with the `DomainBlock` module (tagged hosts-file and firewall blocks).
- Add `Invoke-DomainBlockWorkflow` for Apply, Refresh, and Remove sequences.
- Add self-tests in `tests/Invoke-DomainBlockTest.ps1`.
- Add GitHub Actions (`Test` workflow) to run those tests on Windows.

