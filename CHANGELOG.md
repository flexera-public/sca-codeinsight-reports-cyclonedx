# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Support for component version license expressions from PSE_LICENSE_EXPRESSION table
- License expressions now take precedence over single license selections when available
- Added LEFT JOIN to PSE_LICENSE_EXPRESSION in database queries
- Enhanced license processing logic to prioritize license expressions
- Fallback "NOASSERTION" license entry for inventory items with neither a single license nor a license expression, so they are still included in the report
### Changed
- Updated get_inventory_data() and get_inventory_data_custom() to fetch license expressions
- Modified license handling in report_data.py to check for license expressions first
- Updated XML and JSON report generation to use license expressions when available
- Maintained backward compatibility with existing single-license inventory items
### Fixed
- Changed PDL_LICENSE join from INNER JOIN to LEFT JOIN in get_inventory_data() and get_inventory_data_custom(). Inventory items whose license is set via a license expression only (LICENSE_ID_ is NULL) were being silently excluded from the entire report because the INNER JOIN on PDL_LICENSE filtered them out before license expression support was added.
- Made license field lookups in report_data.py null-safe (.get() instead of direct indexing) to avoid KeyError now that PDL_LICENSE/PSE_LICENSE_EXPRESSION are LEFT JOINed and either side may be NULL.

## [1.7.3] - 2026-08-31
### Added
- CVSSv4 vulnerabilty score
### Fixed
- added missing XML report 

## [1.7.2] - 2026-08-28
### Changed
- Inclusion of License Expression

## [1.7.1] - 2026-07-06
### Changed
- Incoporated all Inventory Custom Fields

## [1.7.0] - 2026-05-20
### Changed
- CycloneDX 1.7 Specification support

## [1.6.0] - 2025-03-02
### Changed
- Added Supplier, Dependency Relationship and Velnerability details

## [1.5.0] - 2025-06-20
### Changed
- Optimized CycloneDX report to run independently using CodeInsight Database using data directly from DB calls rather than Codeinsight REST API's
- Refer Updated README.md file for using cammand line utitlity

## [1.4.2] - 2025-04-03
### Changed
- Updated CycloneDX report json version compliant to 1.6.x

## [1.4.1] - 2024-11-05
### Changed
- Enhanced the VEX report to retrieve annotated vulnerability analysis data for inventory, including all suppressed vulnerabilities.

## [1.4.0] - 2024-10-18
### Changed
- Enhanced VEX report to retrieve annotated vulnerability analysis data.

## [1.3.1] - 2023-10-16
### Changed
- Update common submodule to prep for tomcat upgrade in 2023R4

## [1.3.0] - 2023-09-07
### Changed
- Using common 3.6.8 env/requirements
- Use common module for API and branding etc
### Fixed
- Resove issue with SPDX license mapping
- Improved logging
- unicode cleanup for description
## Added
- Validated with cyclonedx-cli v 0.24.2


## [1.2.0] - 2023-03-21
### Fixed
- Handle failure in purl creation gracefully (custom components will probably be skipped)
- Standardized registration logic
### Added
- Added support for VRD and VEX options vs just auto creating

## [1.1.1] - 2022-10-04
### Fixed
- Updates for validation passing
- common requirements venv for all reports

## [1.1.0] - 2022-06-09
### Added
- Support for project level custom fields
- Add purls
- Add license url

## [1.0.2] - 2022-05-18
### Added
- Initial internal release of CycloneDX Report