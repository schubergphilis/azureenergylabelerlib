.. :changelog:

History
-------

0.0.1 (22-04-2022)
---------------------

* First code creation


0.1.0 (22-06-2022)
------------------

* First release


0.2.0 (23-06-2022)
------------------

* First Release


0.2.1 (23-06-2022)
------------------

* Changed export all parameter


1.0.0 (15-09-2022)
------------------

* - Removed pandas dependency in favor of native python functionality
* - Added support for SAS URLs to export results to a Storage Account
* - Fixed a bug where open days would show as 9999 for subscriptions scoring an A
* - Fixed a typo on the exempted findings json file


1.1.0 (21-09-2022)
------------------

* Added more information to the --export-metrics option output


1.1.1 (22-09-2022)
------------------

* Fixed a bug where Resource Groups lack the exempted_findings property


2.0.0 (04-10-2022)
------------------

* Removed ExemptedPolicy class


3.0.0 (18-10-2022)
------------------

* Microsoft renamed "Azure Security Benchmark" to "Microsoft cloud security benchmark", changing the interface


3.1.0 (07-03-2023)
------------------

* Bump dependencies.


3.1.1 (21-03-2023)
------------------

* Check subscription tenant id on Tenant init


3.2.0 (11-05-2023)
------------------

* Improved how findings are filtered


3.2.1 (07-06-2023)
------------------

* Fixed pagination
* Fixed typos


3.3.0 (22-09-2023)
------------------

* feat: ability added to exclude resource groups from reporting.
