# Changelog

## 1.0.0 - 2026-09-08

First DomainBlock toolkit release.

- Replace one-off root scripts with the `DomainBlock` module (tagged hosts-file and firewall blocks).
- Add `Invoke-DomainBlockWorkflow` for Apply, Refresh, and Remove sequences.
- Isolate unrelated utilities under `Outliers/` with approved Verb-Noun names.
- Add self-tests in `tests/Invoke-DomainBlockTest.ps1`.
- Add GitHub Actions (`Test` workflow) to run those tests on Windows.

