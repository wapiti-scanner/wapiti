# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.12.15] - 2023-05-01
### Changed
- Internal updates.

## [1.12.14] - 2023-04-25

- Minor internal updates.

## [1.12.13] - 2023-04-17
### Changed
- Updated package dependencies. [#30019]

## [1.12.12] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.12.11] - 2023-04-04
### Changed
- Updated package dependencies. [#29854]

## [1.12.10] - 2023-04-03
### Changed
- Internal updates.

## [1.12.9] - 2023-03-28
### Changed
- Minor internal updates.

## [1.12.8] - 2023-03-27
### Added
- (Backup, Boost, Search, Social) Add links on upgrade pages to activate a license key, if you already have one. [#29443]

### Fixed
- Backup: validate if storage details has loaded before attempting to fetch it again. [#29645]

## [1.12.7] - 2023-03-20
### Changed
- Updated package dependencies. [#29471]

## [1.12.6] - 2023-03-08
### Changed
- Switch to use tracking check from connection package [#29187]
- Updated package dependencies. [#29216]

## [1.12.5] - 2023-02-28
### Changed
- Update billing language [#29126]
- Update days of saved backups link to use external link instead of plain link. [#29137]

## [1.12.4] - 2023-02-20
### Changed
- Minor internal updates.

## [1.12.3] - 2023-02-15
### Changed
- Update to React 18. [#28710]

## [1.12.2] - 2023-02-08
### Added
- Add filter to redirect users who have a license to license activation page. [#28509]

### Changed
- Updated package dependencies. [#28682]

## [1.12.1] - 2023-01-30
### Added
- Add track event when user clicks on upgrade storage CTA [#28647]

## [1.12.0] - 2023-01-30
### Added
- Move usage storage level to a global state [#28603]

### Changed
- Backup storage details improvement [#28581]

## [1.11.0] - 2023-01-26
### Added
- Add backup storage UI on backup plugin [#28085]

## [1.10.8] - 2023-01-23
### Fixed
- Clean up JavaScript eslint issues. [#28441]
- Fixes the price display for products with intro offers for the first month. [#28424]

## [1.10.7] - 2023-01-11
### Added
- Setup js tests and add some tests to existing reducers, selectors and hooks [#28130]

### Changed
- Updated package dependencies. [#28127]
- Use `WP_Filesystem` more consistently in `Helper_Script_Manager`. [#28198]

## [1.10.6] - 2022-12-19
### Changed
- Update Backup logo [#27802]

### Fixed
- Update for PHP 8.2 deprecations. [#27949]

## [1.10.5] - 2022-12-06
### Changed
- Updated backup layout to improve consistency and remove redundancy. [#27222]
- Updated package dependencies. [#27340, #27688, #27696, #27697]

## [1.10.4] - 2022-11-28
### Changed
- Rename Jetpack Backup to Jetpack VaultPress Backup [#27432]
- Updated package dependencies. [#26069]

## [1.10.3] - 2022-11-14
### Changed
- Updated package dependencies. [#26930]

## [1.10.2] - 2022-11-07
### Changed
- Updated package dependencies.

### Fixed
- Updated how backup determines if the site has a plan. [#26943]

## [1.10.1] - 2022-11-01
### Changed
- Updated package dependencies. [#27196]

## [1.10.0] - 2022-10-25
### Changed
- Backup: add a new event to track when a customer dismisses a review request. [#26980]
- Updated package dependencies. [#26705]

### Fixed
- Stopped continuous state loading after good backup. [#27014]

## [1.9.2] - 2022-10-19
### Changed
- Updated package dependencies. [#26808]

## [1.9.1] - 2022-10-17
### Changed
- Updated package dependencies. [#26826, #26851]

## [1.9.0] - 2022-10-13
### Added
- Integrate the new connection error message React component into the Backup plugin. [#26545]

### Changed
- Updated package dependencies. [#26790]

## [1.8.4] - 2022-10-11
### Changed
- Updated package dependencies. [#26640, #26683]

## [1.8.3] - 2022-10-05
### Changed
- Updated package dependencies. [#26457]

## [1.8.2] - 2022-09-27
### Changed
- Updated package dependencies.

### Removed
- Removed dependency connection-ui [#26381]

### Fixed
- Do not show header footer on connection screen [#26421]
- Replace antippatern where components are returned from non-functionl components called renderSomething [#26411]

## [1.8.1] - 2022-09-20
### Changed
- Updated package dependencies.

### Fixed
- Allow other non owner admin to see Backup dashboard [#26105]

## [1.8.0] - 2022-09-08
### Added
- Add support for JITMs to Backup plugin [#25945]

### Changed
- Modify review request logic [#25979]
- Updated package dependencies.

### Fixed
- Backup: Fixed Automattic link in admin footer [#26075]

## [1.7.3] - 2022-08-30
### Changed
- Updated package dependencies. [#25694, #25814]

## [1.7.2] - 2022-08-23
### Changed
- Updated package dependencies. [#25338, #25339, #25377, #25628, #25665, #25762, #25764]

## [1.7.1] - 2022-08-09
### Changed
- Updated package dependencies. [#24477, #25265]

## [1.7.0] - 2022-08-03
### Changed
- Removed calls to deprecated components of the soft disconnect system as it is no longer in use. [#25315]
- Updated package dependencies. [#25300, #25315]

## [1.6.0] - 2022-07-26
### Added
- Add plugin review request [#24929]

### Changed
- Updated package dependencies. [#25140]

## [1.5.0] - 2022-07-19
### Changed
- Added page-view and link tracking analytics. [#24998]
- Updated package dependencies. [#25086]

## [1.4.3] - 2022-07-12
### Changed
- Make dashboard text more clear about realtime backups. [#24955]

## [1.4.2] - 2022-07-06
### Changed
- Updated package dependencies. [#24923]

## [1.4.1] - 2022-06-28
### Changed
- Updated package dependencies. [#24827]

## [1.4.0] - 2022-06-21
### Added
- Added UI to support backup warning state [#24680]

### Changed
- Renaming master to trunk. [#24661]
- Updated package dependencies. [#24679]

## [1.3.9] - 2022-06-14
### Changed
- Updated package dependencies. [#24529]

### Removed
- Removed extra headline from connection screen. [#24696]

## [1.3.8] - 2022-06-08
### Changed
- Reorder JS imports for `import/order` eslint rule. [#24601]
- Updated package dependencies. [#24510]

## [1.3.7] - 2022-05-31
### Changed
- Updated package dependencies. [#24432] [#24573] [#24475] [#24505] [#24515]

## [1.3.6] - 2022-05-24
### Changed
- Updated package dependencies. [#24396] [#24449] [#24453] [#24468]

## [1.3.5] - 2022-05-20
### Changed
- Improve the build process to ensure availability of built assets. [#24442]

## [1.3.4] - 2022-05-19
### Changed
- Updated package dependencies. [#24419]

## [1.3.3] - 2022-05-18
### Changed
- Changed method used to disconnect upon deactivation [#24300]
- Updated package dependencies. [#23795] [#24372] [#24153] [#24334] [#24347] [#24344]

### Fixed
- Fix new PHPCS sniffs. [#24366]

## [1.3.2] - 2022-05-10
### Changed
- Updated package dependencies. [#24167]

## [1.3.1] - 2022-05-04
### Changed
- Remove use of `pnpx` in preparation for pnpm 7.0. [#24210]
- Updated package dependencies. [#24095] [#24198]

## [1.3.0] - 2022-04-26
### Changed
- Backup plugin UI now lives in the Backup package

## [1.2.6] - 2022-04-19
### Changed
- Updated package dependencies.

## [1.2.5] - 2022-03-02
### Changed
- Updated package dependencies.

## [1.2.4] - 2022-02-22
### Changed
- Updated package dependencies.

## [1.2.3] - 2022-01-25
### Changed
- Dependency Update - Sync from 1.29 to 1.29

## [1.2.2] - 2022-01-18
### Changed
- Updated package dependencies.

## [1.2.1] - 2022-01-13
### Changed
- Updated package dependencies.

## [1.2.0] - 2022-01-04
### Changed
- Switch to pcov for code coverage.
- Updated package dependencies
- Updated package textdomain from `jetpack` to `jetpack-backup-pkg`.

## [1.1.11] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.1.10] - 2021-11-30
### Changed
- Updated package dependencies.

## [1.1.9] - 2021-11-23
### Changed
- Updated package dependencies.

## [1.1.8] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [1.1.7] - 2021-10-26
### Changed
- Updated package dependencies.

## [1.1.6] - 2021-10-13
### Changed
- Updated package dependencies.

## [1.1.5] - 2021-10-12
### Changed
- Updated package dependencies

## [1.1.4] - 2021-09-28
### Fixed
- Register WP hooks even if WP isn't loaded yet.

## [1.1.3] - 2021-08-31
### Changed
- Bump changelogger version
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).
- Updated package dependencies.

## [1.1.2] - 2021-08-12
### Added
- Add package version tracking.

## [1.1.1] - 2021-07-27
### Added
- Add a package version constant.

### Changed
- Updated package dependencies.

## [1.1.0] - 2021-06-29
### Added
- Add backup-helper-script endpoints under the jetpack/v4 namespace.
- Add backup real time endpoints.

## [1.0.6] - 2021-05-25
### Changed
- Updated package dependencies.

## [1.0.5] - 2021-04-27
### Changed
- Updated package dependencies.

## [1.0.4] - 2021-03-30
### Added
- Composer alias for dev-master, to improve dependencies

### Changed
- Update package dependencies.

## [1.0.3] - 2021-01-19

- Add mirror-repo information to all current composer packages
- Monorepo: Reorganize all projects

## [1.0.2] - 2019-11-08

- Packages: Use classmap instead of PSR-4

## 1.0.0 - 2019-10-29

- Add API endpoints and Jetpack Backup package for managing Help…

[1.12.15]: https://github.com/Automattic/jetpack-backup/compare/v1.12.14...v1.12.15
[1.12.14]: https://github.com/Automattic/jetpack-backup/compare/v1.12.13...v1.12.14
[1.12.13]: https://github.com/Automattic/jetpack-backup/compare/v1.12.12...v1.12.13
[1.12.12]: https://github.com/Automattic/jetpack-backup/compare/v1.12.11...v1.12.12
[1.12.11]: https://github.com/Automattic/jetpack-backup/compare/v1.12.10...v1.12.11
[1.12.10]: https://github.com/Automattic/jetpack-backup/compare/v1.12.9...v1.12.10
[1.12.9]: https://github.com/Automattic/jetpack-backup/compare/v1.12.8...v1.12.9
[1.12.8]: https://github.com/Automattic/jetpack-backup/compare/v1.12.7...v1.12.8
[1.12.7]: https://github.com/Automattic/jetpack-backup/compare/v1.12.6...v1.12.7
[1.12.6]: https://github.com/Automattic/jetpack-backup/compare/v1.12.5...v1.12.6
[1.12.5]: https://github.com/Automattic/jetpack-backup/compare/v1.12.4...v1.12.5
[1.12.4]: https://github.com/Automattic/jetpack-backup/compare/v1.12.3...v1.12.4
[1.12.3]: https://github.com/Automattic/jetpack-backup/compare/v1.12.2...v1.12.3
[1.12.2]: https://github.com/Automattic/jetpack-backup/compare/v1.12.1...v1.12.2
[1.12.1]: https://github.com/Automattic/jetpack-backup/compare/v1.12.0...v1.12.1
[1.12.0]: https://github.com/Automattic/jetpack-backup/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/Automattic/jetpack-backup/compare/v1.10.8...v1.11.0
[1.10.8]: https://github.com/Automattic/jetpack-backup/compare/v1.10.7...v1.10.8
[1.10.7]: https://github.com/Automattic/jetpack-backup/compare/v1.10.6...v1.10.7
[1.10.6]: https://github.com/Automattic/jetpack-backup/compare/v1.10.5...v1.10.6
[1.10.5]: https://github.com/Automattic/jetpack-backup/compare/v1.10.4...v1.10.5
[1.10.4]: https://github.com/Automattic/jetpack-backup/compare/v1.10.3...v1.10.4
[1.10.3]: https://github.com/Automattic/jetpack-backup/compare/v1.10.2...v1.10.3
[1.10.2]: https://github.com/Automattic/jetpack-backup/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/Automattic/jetpack-backup/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/Automattic/jetpack-backup/compare/v1.9.2...v1.10.0
[1.9.2]: https://github.com/Automattic/jetpack-backup/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/Automattic/jetpack-backup/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/Automattic/jetpack-backup/compare/v1.8.4...v1.9.0
[1.8.4]: https://github.com/Automattic/jetpack-backup/compare/v1.8.3...v1.8.4
[1.8.3]: https://github.com/Automattic/jetpack-backup/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/Automattic/jetpack-backup/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/Automattic/jetpack-backup/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/Automattic/jetpack-backup/compare/v1.7.3...v1.8.0
[1.7.3]: https://github.com/Automattic/jetpack-backup/compare/v1.7.2...v1.7.3
[1.7.2]: https://github.com/Automattic/jetpack-backup/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-backup/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-backup/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Automattic/jetpack-backup/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Automattic/jetpack-backup/compare/v1.4.3...v1.5.0
[1.4.3]: https://github.com/Automattic/jetpack-backup/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/Automattic/jetpack-backup/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/Automattic/jetpack-backup/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/Automattic/jetpack-backup/compare/v1.3.9...v1.4.0
[1.3.9]: https://github.com/Automattic/jetpack-backup/compare/v1.3.8...v1.3.9
[1.3.8]: https://github.com/Automattic/jetpack-backup/compare/v1.3.7...v1.3.8
[1.3.7]: https://github.com/Automattic/jetpack-backup/compare/v1.3.6...v1.3.7
[1.3.6]: https://github.com/Automattic/jetpack-backup/compare/v1.3.5...v1.3.6
[1.3.5]: https://github.com/Automattic/jetpack-backup/compare/v1.3.4...v1.3.5
[1.3.4]: https://github.com/Automattic/jetpack-backup/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/Automattic/jetpack-backup/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/Automattic/jetpack-backup/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/Automattic/jetpack-backup/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Automattic/jetpack-backup/compare/v1.2.6...v1.3.0
[1.2.6]: https://github.com/Automattic/jetpack-backup/compare/v1.2.5...v1.2.6
[1.2.5]: https://github.com/Automattic/jetpack-backup/compare/v1.2.4...v1.2.5
[1.2.4]: https://github.com/Automattic/jetpack-backup/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/Automattic/jetpack-backup/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/Automattic/jetpack-backup/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/Automattic/jetpack-backup/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Automattic/jetpack-backup/compare/v1.1.11...v1.2.0
[1.1.11]: https://github.com/Automattic/jetpack-backup/compare/v1.1.10...v1.1.11
[1.1.10]: https://github.com/Automattic/jetpack-backup/compare/v1.1.9...v1.1.10
[1.1.9]: https://github.com/Automattic/jetpack-backup/compare/v1.1.8...v1.1.9
[1.1.8]: https://github.com/Automattic/jetpack-backup/compare/v1.1.7...v1.1.8
[1.1.7]: https://github.com/Automattic/jetpack-backup/compare/v1.1.6...v1.1.7
[1.1.6]: https://github.com/Automattic/jetpack-backup/compare/v1.1.5...v1.1.6
[1.1.5]: https://github.com/Automattic/jetpack-backup/compare/v1.1.4...v1.1.5
[1.1.4]: https://github.com/Automattic/jetpack-backup/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/Automattic/jetpack-backup/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/Automattic/jetpack-backup/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Automattic/jetpack-backup/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Automattic/jetpack-backup/compare/v1.0.6...v1.1.0
[1.0.6]: https://github.com/Automattic/jetpack-backup/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/Automattic/jetpack-backup/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/Automattic/jetpack-backup/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Automattic/jetpack-backup/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Automattic/jetpack-backup/compare/v1.0.0...v1.0.2
