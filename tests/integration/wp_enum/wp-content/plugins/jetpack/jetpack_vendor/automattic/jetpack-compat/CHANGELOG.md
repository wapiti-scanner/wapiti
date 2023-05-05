# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.6] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.7.5] - 2022-11-28
### Changed
- Updated package dependencies. [#27043]

## [1.7.4] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [1.7.3] - 2022-06-21
### Changed
- Renaming master to trunk. [#24661]

## [1.7.2] - 2022-05-18
### Fixed
- Fix new PHPCS sniffs. [#24366]

## [1.7.1] - 2022-04-26
### Changed
- Updated package dependencies.

## [1.7.0] - 2022-03-23
### Added
- Migrated GlotPress locale classes into compat pkg

## [1.6.8] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.6.7] - 2021-10-19
### Changed
- Updated package dependencies.

## [1.6.6] - 2021-09-28
### Fixed
- Register WP hooks even if WP isn't loaded yet.

## [1.6.5] - 2021-05-25
### Changed
- Updated package dependencies.

## [1.6.4] - 2021-04-27
### Changed
- Updated package dependencies.

## [1.6.3] - 2021-03-30
### Added
- Composer alias for dev-master, to improve dependencies

### Changed
- Update package dependencies.

## [1.6.2] - 2021-02-05

- CI: Make tests more generic

## [1.6.1] - 2021-01-19

- Add mirror-repo information to all current composer packages
- Monorepo: Reorganize all projects

## [1.6.0] - 2020-12-07

- Pin dependencies
- Packages: Update for PHP 8 testing

## [1.5.1] - 2020-10-28

- Updated PHPCS: Packages and Debugger

## [1.5.0] - 2020-10-01

- API: Remove the constant `JETPACK_CLIENT__HTTPS`.

## [1.4.0] - 2020-08-19

- Compat Package: Fix method declaration compatibility

## [1.3.0] - 2020-06-10

- Various: Update use of whitelist/blacklist

## [1.2.0] - 2020-04-28

- Correct inline documentation "Array" type
- Compat: use require_once instead of jetpack_require_lib()

## [1.1.0] - 2020-03-10

- Sync Package: Add readme skeleton (#14945)

## [1.0.5] - 2019-11-08

- Packages: Use classmap instead of PSR-4

## [1.0.4] - 2019-11-08

- Move fix_url_for_bad_hosts from Jetpack class to Connection pa…

## [1.0.3] - 2019-10-29

- PHPCS: Rest of the packages
- Update Prettier and reformat files

## [1.0.2] - 2019-09-20

- Docs: Unify usage of @package phpdoc tags
- Janitorial: Remove the leading backslash from namespaces

## [1.0.1] - 2019-09-14

- Sync: Add return for deprecated Jetpack_Sync_Settings functions with expected return value

## 1.0.0 - 2019-09-14

- Jetpack 7.5: Back compatibility package

[1.7.6]: https://github.com/Automattic/jetpack-compat/compare/v1.7.5...v1.7.6
[1.7.5]: https://github.com/Automattic/jetpack-compat/compare/v1.7.4...v1.7.5
[1.7.4]: https://github.com/Automattic/jetpack-compat/compare/v1.7.3...v1.7.4
[1.7.3]: https://github.com/Automattic/jetpack-compat/compare/v1.7.2...v1.7.3
[1.7.2]: https://github.com/Automattic/jetpack-compat/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-compat/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-compat/compare/v1.6.8...v1.7.0
[1.6.8]: https://github.com/Automattic/jetpack-compat/compare/v1.6.7...v1.6.8
[1.6.7]: https://github.com/Automattic/jetpack-compat/compare/v1.6.6...v1.6.7
[1.6.6]: https://github.com/Automattic/jetpack-compat/compare/v1.6.5...v1.6.6
[1.6.5]: https://github.com/Automattic/jetpack-compat/compare/v1.6.4...v1.6.5
[1.6.4]: https://github.com/Automattic/jetpack-compat/compare/v1.6.3...v1.6.4
[1.6.3]: https://github.com/Automattic/jetpack-compat/compare/v1.6.2...v1.6.3
[1.6.2]: https://github.com/Automattic/jetpack-compat/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/Automattic/jetpack-compat/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-compat/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/Automattic/jetpack-compat/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Automattic/jetpack-compat/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Automattic/jetpack-compat/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Automattic/jetpack-compat/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Automattic/jetpack-compat/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Automattic/jetpack-compat/compare/v1.0.5...v1.1.0
[1.0.5]: https://github.com/Automattic/jetpack-compat/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/Automattic/jetpack-compat/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Automattic/jetpack-compat/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Automattic/jetpack-compat/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Automattic/jetpack-compat/compare/v1.0.0...v1.0.1
