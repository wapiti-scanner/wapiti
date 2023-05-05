# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.25] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.4.24] - 2023-02-20
### Changed
- Minor internal updates.

## [1.4.23] - 2023-01-11
### Changed
- Updated package dependencies.

## [1.4.22] - 2022-12-02
### Changed
- Updated package dependencies. [#27688]

## [1.4.21] - 2022-11-22
### Added
- Add a guard in `functions.php` against being loaded twice from different copies of the package. [#27475]

### Changed
- Updated package dependencies. [#27043]

## [1.4.20] - 2022-11-07
### Fixed
- Ensure that User_Agent is loaded in environments without autoload enabled. (e.g.: WordPress.com and Super Cache) [#27223]

## [1.4.19] - 2022-10-25
### Changed
- Update `wp_unslash` wrapper to possibly run on wpcom before WordPress is loaded. [#26971]

## [1.4.18] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [1.4.17] - 2022-06-21
### Changed
- Renaming master to trunk.

## [1.4.16] - 2022-04-26
### Changed
- Updated package dependencies.

## [1.4.15] - 2022-04-19
### Changed
- PHPCS: Fix `WordPress.Security.ValidatedSanitizedInput`

## [1.4.14] - 2022-03-29
### Changed
- Microperformance: Use === null instead of is_null

## [1.4.13] - 2022-02-09
### Fixed
- Fixed some new PHPCS warnings.

## [1.4.12] - 2022-01-25
### Changed
- Updated package dependencies.

## [1.4.11] - 2022-01-04
### Changed
- Switch to pcov for code coverage.
- Updated package dependencies

## [1.4.10] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.4.9] - 2021-11-16
### Fixed
- Verify $_SERVER['HTTP_USER_AGENT'] exists before use.

## [1.4.8] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [1.4.7] - 2021-10-19
### Deprecated
- General: remove numerous long-deprecated functions.

## [1.4.6] - 2021-10-13
### Changed
- Updated package dependencies.

## [1.4.5] - 2021-10-12
### Changed
- Updated package dependencies

## [1.4.4] - 2021-09-28
### Changed
- Updated package dependencies.

## [1.4.3] - 2021-08-31
### Changed
- Run composer update on test-php command instead of phpunit.
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).
- Updated versions in annotations.

## [1.4.2] - 2021-05-25
### Changed
- Updated package dependencies.

## [1.4.1] - 2021-04-27
### Changed
- Updated package dependencies.

## [1.4.0] - 2021-03-30
### Added
- Added Opera Desktop detection
- Composer alias for dev-master, to improve dependencies

### Changed
- Update package dependencies.

### Fixed
- Use `composer update` rather than `install` in scripts, as composer.lock isn't checked in.

## [1.3.2] - 2021-02-05

- CI: Make tests more generic

## [1.3.1] - 2021-01-19

- Add mirror-repo information to all current composer packages
- Monorepo: Reorganize all projects

## [1.3.0] - 2020-12-09

- Codesniffer: Update mediawiki/mediawiki-codesniffer dependency
- Pin dependencies
- Packages: Update for PHP 8 testing

## [1.2.1] - 2020-11-10

- Improve PHP 8 compatibility
- Updated PHPCS: Packages and Debugger

## [1.2.0] - 2020-10-19

- Replaced intval() with (int) as part of issue #17432.

## [1.1.0] - 2020-08-13

- CI: Try collect js coverage

## 1.0.0 - 2020-06-25

- Moving jetpack_is_mobile into a package

[1.4.25]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.24...v1.4.25
[1.4.24]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.23...v1.4.24
[1.4.23]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.22...v1.4.23
[1.4.22]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.21...v1.4.22
[1.4.21]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.20...v1.4.21
[1.4.20]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.19...v1.4.20
[1.4.19]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.18...v1.4.19
[1.4.18]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.17...v1.4.18
[1.4.17]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.16...v1.4.17
[1.4.16]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.15...v1.4.16
[1.4.15]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.14...v1.4.15
[1.4.14]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.13...v1.4.14
[1.4.13]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.12...v1.4.13
[1.4.12]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.11...v1.4.12
[1.4.11]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.10...v1.4.11
[1.4.10]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.9...v1.4.10
[1.4.9]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.8...v1.4.9
[1.4.8]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.7...v1.4.8
[1.4.7]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.6...v1.4.7
[1.4.6]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.5...v1.4.6
[1.4.5]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.4...v1.4.5
[1.4.4]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.3...v1.4.4
[1.4.3]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/Automattic/jetpack-device-detection/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/Automattic/jetpack-device-detection/compare/v1.3.2...v1.4.0
[1.3.2]: https://github.com/Automattic/jetpack-device-detection/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/Automattic/jetpack-device-detection/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Automattic/jetpack-device-detection/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/Automattic/jetpack-device-detection/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Automattic/jetpack-device-detection/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Automattic/jetpack-device-detection/compare/v1.0.0...v1.1.0
