# Changelog

All notable changes to this project will be documented in this file.
## [1.2.0] - 2026-10-01

### Bug Fixes

- *(ci)* Remove pip cache lookup in setup-python

- *(ci)* Correct appinspect report data-format


### Features

- Add modular alert action, saved search alerts, and slim/bump-my-version tooling

- *(ta)* Add bulk target scanning support via CSV lookup

- *(ta)* Implement full certificate trust chain extraction and intermediate CA audit alerts

- *(ta)* Add OCSP/CRL revocation checking and fix bumpversion config filename


### Ci

- Automate changelog generation and GitHub releases with git-cliff

