# Changelog

## [4.0.0](https://github.com/schubergphilis/azureenergylabelerlib/compare/v3.3.4...v4.0.0) (2026-03-06)


### ⚠ BREAKING CHANGES

* migration to paleofuturistic python template
* remove files from previous build setup based on pipenv and custom _CI
* migration to uv and python 3.12

### Features

* added validation azure resource group names. And using this validation for denied_resource_group_names. ([8b7bb85](https://github.com/schubergphilis/azureenergylabelerlib/commit/8b7bb85dc13662bae299590823b384877834ac27))
* added validation for azure resource group names ([0a15d54](https://github.com/schubergphilis/azureenergylabelerlib/commit/0a15d54052df14976f64c331a91c4f9ce7a7b38c))
* migration to paleofuturistic python template ([9a3f910](https://github.com/schubergphilis/azureenergylabelerlib/commit/9a3f9105dee27934534f0d3b608174c4f6586c3c))
* migration to uv and python 3.12 ([49b7cde](https://github.com/schubergphilis/azureenergylabelerlib/commit/49b7cde5e607a526ca70f1491a83387350be373f))


### Miscellaneous Chores

* remove files from previous build setup based on pipenv and custom _CI ([91f5961](https://github.com/schubergphilis/azureenergylabelerlib/commit/91f5961b17348d6562e679e3ecb9a247cf2ffccb))

## 3.3.4 (23-02-2026)

* Fix for breaking change in azure.mgmt.resource 25.0.0

## 3.3.3 (06-06-2024)

* Pin policy api version.

## 3.3.2 (05-10-2023)

* feat: added validation for azure resource group names.

## 3.3.1 (02-10-2023)

* fix: denied_resource_group_names is optional in the rest of the code, so also should be in Subscription.

## 3.3.0 (22-09-2023)

* feat: ability added to exclude resource groups from reporting.

## 3.2.1 (07-06-2023)

* Fixed pagination
* Fixed typos

## 3.2.0 (11-05-2023)

* Improved how findings are filtered

## 3.1.1 (21-03-2023)

* Check subscription tenant id on Tenant init

## 3.1.0 (07-03-2023)

* Bump dependencies.

## 3.0.0 (18-10-2022)

* Microsoft renamed "Azure Security Benchmark" to "Microsoft cloud security benchmark", changing the interface

## 2.0.0 (04-10-2022)

* Removed ExemptedPolicy class

## 1.1.1 (22-09-2022)

* Fixed a bug where Resource Groups lack the exempted_findings property

## 1.1.0 (21-09-2022)

* Added more information to the --export-metrics option output

## 1.0.0 (15-09-2022)

* Removed pandas dependency in favor of native python functionality
* Added support for SAS URLs to export results to a Storage Account
* Fixed a bug where open days would show as 9999 for subscriptions scoring an A
* Fixed a typo on the exempted findings json file

## 0.2.1 (23-06-2022)

* Changed export all parameter

## 0.2.0 (23-06-2022)

* First Release

## 0.1.0 (22-06-2022)

* First release

## 0.0.1 (22-04-2022)

* First code creation
