# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.2] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.8.1] - 2023-02-20
### Changed
- Minor internal updates.

## [1.8.0] - 2023-02-08
### Added
- After connection flow, load unattached licenses. If any of them match the product that's being connected, redirect users to the license activation page. [#28509]

## [1.7.14] - 2023-01-11
### Changed
- Updated package dependencies.

## [1.7.13] - 2022-12-02
### Changed
- Updated package dependencies. [#27688]

## [1.7.12] - 2022-11-22
### Changed
- Updated package dependencies. [#27043]

## [1.7.11] - 2022-10-25
### Changed
- Updated package dependencies. [#26705]

## [1.7.10] - 2022-09-20
### Changed
- Updated package dependencies.

## [1.7.9] - 2022-09-08
### Changed
- Updated package dependencies.

## [1.7.8] - 2022-08-29
### Changed
- Updated package dependencies.

## [1.7.7] - 2022-08-23
### Changed
- Updated package dependencies. [#25628]

## [1.7.6] - 2022-08-03
### Changed
- Updated package dependencies. [#25300, #25315]

## [1.7.5] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [1.7.4] - 2022-06-21
### Changed
- Renaming master to trunk.

## [1.7.3] - 2022-06-14
### Changed
- Updated package dependencies. [#24529]

## [1.7.2] - 2022-05-04
### Changed
- Updated package dependencies. [#24095]

### Deprecated
- Moved the options class into Connection. [#24095]

## [1.7.1] - 2022-04-26
### Changed
- Updated package dependencies.

## [1.7.0] - 2022-04-19
### Changed
- Moved licensing endpoints from the Jetpack plugin to the Licensing package

## [1.6.4] - 2022-04-12
### Changed
- Updated package dependencies.

## [1.6.3] - 2022-03-02
### Changed
- Updated package dependencies.

## [1.6.2] - 2022-01-25
### Changed
- Updated package dependencies.

## [1.6.1] - 2022-01-18
### Changed
- Updated package dependencies.

## [1.6.0] - 2022-01-04
### Changed
- Switch to pcov for code coverage.
- Updated package dependencies
- Updated package textdomain from `jetpack` to `jetpack-licensing`.

## [1.5.4] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.5.3] - 2021-12-03
### Changed
- Increases the timeout of the license activation request from 10 to 30 seconds.

## [1.5.2] - 2021-11-30
### Changed
- Updated package dependencies.

## [1.5.1] - 2021-11-23
### Changed
- Updated package dependencies.

## [1.5.0] - 2021-11-16
### Added
- Add a test for update to WPCOM return change.
- Added get_license_activation_notice_dismiss() function.

## [1.4.9] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [1.4.8] - 2021-10-19
### Changed
- Updated package dependencies.

## [1.4.7] - 2021-10-12
### Changed
- Updated package dependencies

## [1.4.6] - 2021-09-28
### Changed
- Updated package dependencies.

## [1.4.5] - 2021-08-31
### Changed
- Run composer update on test-php command instead of phpunit.
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).
- Updated versions in annotations.

## [1.4.4] - 2021-07-27
### Changed
- Updated package dependencies.

## [1.4.3] - 2021-06-29
### Changed
- Updated package dependencies.

## [1.4.2] - 2021-05-25
### Changed
- Updated package dependencies.

## [1.4.1] - 2021-04-27
### Changed
- Updated package dependencies.

## [1.4.0] - 2021-03-30
### Added
- Composer alias for dev-master, to improve dependencies
- Dashboard: add new option to input license key.

### Changed
- Replace usage of deprecated is_active method
- Update package dependencies.

### Fixed
- Fix stored licenses not being attached on option creation
- Use `composer update` rather than `install` in scripts, as composer.lock isn't checked in.

## [1.3.4] - 2021-02-23

- CI: Make tests more generic
- codesniffer: Hack around mediawiki-codesniffer bug

## [1.3.3] - 2021-02-08

- Update dependencies to latest stable

## [1.3.2] - 2021-01-28

- Update dependencies to latest stable

## [1.3.1] - 2021-01-26

- Add mirror-repo information to all current composer packages
- Monorepo: Reorganize all projects

## [1.3.0] - 2021-01-05

- Pin dependencies
- Packages: Update for PHP 8 testing

## [1.2.4] - 2020-11-24

- Version packages for release

## [1.2.3] - 2020-11-24

- Updated PHPCS: Packages and Debugger

## [1.2.2] - 2020-11-05

- Update dependencies to latest stable

## [1.2.1] - 2020-10-29

- Update dependencies to latest stable

## [1.2.0] - 2020-10-27

- Licensing: use Oxford comma in error message

## [1.1.4] - 2020-10-14

- Update dependencies to latest stable

## [1.1.3] - 2020-10-09

- Update dependencies to latest stable

## [1.1.2] - 2020-10-06

- Update dependencies to latest stable

## [1.1.1] - 2020-10-01

- Update dependencies to latest stable

## [1.1.0] - 2020-09-29

- Update dependencies to latest stable

## 1.0.0 - 2020-09-24

- Licensing: Add support for Jetpack licenses

[1.8.2]: https://github.com/Automattic/jetpack-licensing/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/Automattic/jetpack-licensing/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.14...v1.8.0
[1.7.14]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.13...v1.7.14
[1.7.13]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.12...v1.7.13
[1.7.12]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.11...v1.7.12
[1.7.11]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.10...v1.7.11
[1.7.10]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.9...v1.7.10
[1.7.9]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.8...v1.7.9
[1.7.8]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.7...v1.7.8
[1.7.7]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.6...v1.7.7
[1.7.6]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.5...v1.7.6
[1.7.5]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.4...v1.7.5
[1.7.4]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.3...v1.7.4
[1.7.3]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.2...v1.7.3
[1.7.2]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-licensing/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-licensing/compare/v1.6.4...v1.7.0
[1.6.4]: https://github.com/Automattic/jetpack-licensing/compare/v1.6.3...v1.6.4
[1.6.3]: https://github.com/Automattic/jetpack-licensing/compare/v1.6.2...v1.6.3
[1.6.2]: https://github.com/Automattic/jetpack-licensing/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/Automattic/jetpack-licensing/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-licensing/compare/v1.5.4...v1.6.0
[1.5.4]: https://github.com/Automattic/jetpack-licensing/compare/v1.5.3...v1.5.4
[1.5.3]: https://github.com/Automattic/jetpack-licensing/compare/v1.5.2...v1.5.3
[1.5.2]: https://github.com/Automattic/jetpack-licensing/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/Automattic/jetpack-licensing/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.9...v1.5.0
[1.4.9]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.8...v1.4.9
[1.4.8]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.7...v1.4.8
[1.4.7]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.6...v1.4.7
[1.4.6]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.5...v1.4.6
[1.4.5]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.4...v1.4.5
[1.4.4]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.3...v1.4.4
[1.4.3]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/Automattic/jetpack-licensing/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/Automattic/jetpack-licensing/compare/v1.3.4...v1.4.0
[1.3.4]: https://github.com/Automattic/jetpack-licensing/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/Automattic/jetpack-licensing/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/Automattic/jetpack-licensing/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/Automattic/jetpack-licensing/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Automattic/jetpack-licensing/compare/v1.2.4...v1.3.0
[1.2.4]: https://github.com/Automattic/jetpack-licensing/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/Automattic/jetpack-licensing/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/Automattic/jetpack-licensing/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/Automattic/jetpack-licensing/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Automattic/jetpack-licensing/compare/v1.1.4...v1.2.0
[1.1.4]: https://github.com/Automattic/jetpack-licensing/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/Automattic/jetpack-licensing/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/Automattic/jetpack-licensing/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Automattic/jetpack-licensing/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Automattic/jetpack-licensing/compare/v1.0.0...v1.1.0
