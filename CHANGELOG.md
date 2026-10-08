# Changelog

All notable changes to this project will be documented in this file.
## [2.1.1] - 2026-10-08

### Bug Fixes

- *(ta)* Bundle missing dependencies and enable UI visibility

- *(ci)* Correct .bumpversion current_version

- *(ta)* Bundle missing dependencies, enable UI visibility, and fix date parsing

- *(ta)* Resolve web.conf AppInspect validation error


### Documentation

- *(changelog)* Update CHANGELOG.md for v2.1.0 [skip ci]

- *(changelog)* Update CHANGELOG.md for v2.1.1 [skip ci]

## [2.1.0] - 2026-10-07

### Documentation

- *(changelog)* Update CHANGELOG.md for v2.0.1 [skip ci]


### Features

- *(ta)* Implement legacy TLS auditing, unified SAN parsing, and fix OCSP proxy routing


### Miscellaneous Tasks

- Remove deleted app.conf from bumpversion tracking

## [2.0.1] - 2026-10-03

### Bug Fixes

- *(ta)* Add bin/lib path fallback and harden input error handling

- *(ta)* Correct props.conf CIM mappings and evaluations

- *(ta)* Finalize props.conf, inputs.conf defaults, and spec definitions

- *(ta)* Declare python.version = python3 in inputs.conf for AppInspect compliance


### Documentation

- *(changelog)* Update CHANGELOG.md for v2.0.0 [skip ci]

- *(changelog)* Update CHANGELOG.md for v2.0.1 [skip ci]

- *(changelog)* Update CHANGELOG.md for v2.0.1 [skip ci]

- *(changelog)* Update CHANGELOG.md for v2.0.1 [skip ci]

## [2.0.0] - 2026-10-03

### Bug Fixes

- *(ci)* Remove pip cache lookup in setup-python action

- *(ci)* Use correct PyPI package splunk_add_on_ucc_framework

- *(ci)* Invoke appinspect via python -m splunk_appinspect.main

- *(ci)* Invoke splunk-appinspect directly via pythonLocation bin path


### Documentation

- *(changelog)* Update CHANGELOG.md for v1.3.2 [skip ci]

- *(changelog)* Update CHANGELOG.md for v2.0.0 [skip ci]

- *(changelog)* Update CHANGELOG.md for v2.0.0 [skip ci]


### Features

- *(core)* Complete v2.0.0 migration for Splunk Cloud and UCC standards

## [1.3.2] - 2026-10-01

### Bug Fixes

- *(ta)* Align target_host param in extract_cert_data and clean syntax encoding


### Documentation

- *(changelog)* Update CHANGELOG.md for v1.3.1 [skip ci]

## [1.3.1] - 2026-10-01

### Bug Fixes

- *(ta)* Correct modular input xml streaming, ocsp get fallback, and ssrf resolution


### Documentation

- *(changelog)* Update CHANGELOG.md for v1.3.0 [skip ci]

## [1.3.0] - 2026-10-01

### Bug Fixes

- *(ta)* Remove prohibited maxDataSize and maxTotalDataSizeMB from indexes.conf


### Documentation

- *(changelog)* Update CHANGELOG.md for v1.2.2 [skip ci]


### Features

- Declare dedicated ssl_cert index, macros, and metadata permissions

- *(app)* Add app navigation styling and ensure index configurations

## [1.2.1] - 2026-10-01

### Bug Fixes

- *(dashboards)* Wire up filters, add revocation KPI card, and separate audit rows


### Documentation

- *(changelog)* Update CHANGELOG.md for v1.2.0 [skip ci]

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

