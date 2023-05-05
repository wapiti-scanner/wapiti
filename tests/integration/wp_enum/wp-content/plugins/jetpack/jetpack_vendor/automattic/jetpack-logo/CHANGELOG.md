# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.1] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.6.0] - 2023-04-04
### Added
- Add new method to get a base64 encoded SVG of the Jetpack logo. [#29418]

## [1.5.22] - 2023-02-20
### Changed
- Minor internal updates.

## [1.5.21] - 2023-01-30
### Changed
- Updated styles for Just in Time Messages (notices) [#27515]

## [1.5.20] - 2022-12-02
### Changed
- Updated package dependencies. [#27688]

## [1.5.19] - 2022-11-22
### Changed
- Updated package dependencies. [#27043]

## [1.5.18] - 2022-11-07
### Changed
- Updated package dependencies.

## [1.5.17] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [1.5.16] - 2022-06-21
### Changed
- Renaming master to trunk. [#24661]

## [1.5.15] - 2022-04-26
### Changed
- Updated package dependencies.

## [1.5.14] - 2022-01-25
### Changed
- Updated package dependencies.

## [1.5.13] - 2022-01-04
### Changed
- Switch to pcov for code coverage.
- Updated package dependencies

## [1.5.12] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.5.11] - 2021-11-30
### Changed
- Colors: update Jetpack Primary color to match latest brand book.

## [1.5.10] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [1.5.9] - 2021-10-13
### Changed
- Updated package dependencies.

## [1.5.8] - 2021-10-07
### Changed
- Updated package dependencies

## [1.5.7] - 2021-09-28
### Changed
- Updated package dependencies.

## [1.5.6] - 2021-08-30
### Changed
- Run composer update on test-php command instead of phpunit
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).
- update annotations versions

## [1.5.5] - 2021-05-25
### Changed
- Updated package dependencies.

## [1.5.4] - 2021-04-27
### Changed
- Updated package dependencies.

## [1.5.3] - 2021-03-30
### Added
- Composer alias for dev-master, to improve dependencies

### Changed
- Update package dependencies.

### Fixed
- Use `composer update` rather than `install` in scripts, as composer.lock isn't checked in.

## [1.5.2] - 2021-02-05

- CI: Make tests more generic

## [1.5.1] - 2021-01-19

- Add mirror-repo information to all current composer packages
- Monorepo: Reorganize all projects

## [1.5.0] - 2020-12-07

- Pin dependencies
- Packages: Update for PHP 8 testing

## [1.4.0] - 2020-08-13

- CI: Try collect js coverage

## [1.3.0] - 2020-06-22

- PHPCS: Clean up the packages
- PHPCS Updates after WPCS 2.3

## [1.2.0] - 2020-03-27

- Use dynamic Jetpack logos on JITMs

## [1.1.4] - 2019-11-08

- Packages: Use classmap instead of PSR-4

## [1.1.2] - 2019-10-28

- Packages: Add gitattributes files to all packages that need th…

## [1.1.1] - 2019-09-20

- Docs: Unify usage of @package phpdoc tags

## [1.1.0] - 2019-06-11

- Feature/jetpack packages pt 1. (May 31 - June 6)
- Update/package logo add gray
- Packages: Move JITM tests to package and fix deps
- Update Jetpack to use new JITM package
- Packages: Make logo package tests independent

## 1.0.0 - 2019-05-29

- Packages: Add a basic Jetpack Logo package

[1.6.1]: https://github.com/Automattic/jetpack-logo/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-logo/compare/v1.5.22...v1.6.0
[1.5.22]: https://github.com/Automattic/jetpack-logo/compare/v1.5.21...v1.5.22
[1.5.21]: https://github.com/Automattic/jetpack-logo/compare/v1.5.20...v1.5.21
[1.5.20]: https://github.com/Automattic/jetpack-logo/compare/v1.5.19...v1.5.20
[1.5.19]: https://github.com/Automattic/jetpack-logo/compare/v1.5.18...v1.5.19
[1.5.18]: https://github.com/Automattic/jetpack-logo/compare/v1.5.17...v1.5.18
[1.5.17]: https://github.com/Automattic/jetpack-logo/compare/v1.5.16...v1.5.17
[1.5.16]: https://github.com/Automattic/jetpack-logo/compare/v1.5.15...v1.5.16
[1.5.15]: https://github.com/Automattic/jetpack-logo/compare/v1.5.14...v1.5.15
[1.5.14]: https://github.com/Automattic/jetpack-logo/compare/v1.5.13...v1.5.14
[1.5.13]: https://github.com/Automattic/jetpack-logo/compare/v1.5.12...v1.5.13
[1.5.12]: https://github.com/Automattic/jetpack-logo/compare/v1.5.11...v1.5.12
[1.5.11]: https://github.com/Automattic/jetpack-logo/compare/v1.5.10...v1.5.11
[1.5.10]: https://github.com/Automattic/jetpack-logo/compare/v1.5.9...v1.5.10
[1.5.9]: https://github.com/Automattic/jetpack-logo/compare/v1.5.8...v1.5.9
[1.5.8]: https://github.com/Automattic/jetpack-logo/compare/v1.5.7...v1.5.8
[1.5.7]: https://github.com/Automattic/jetpack-logo/compare/v1.5.6...v1.5.7
[1.5.6]: https://github.com/Automattic/jetpack-logo/compare/v1.5.5...v1.5.6
[1.5.5]: https://github.com/Automattic/jetpack-logo/compare/v1.5.4...v1.5.5
[1.5.4]: https://github.com/Automattic/jetpack-logo/compare/v1.5.3...v1.5.4
[1.5.3]: https://github.com/Automattic/jetpack-logo/compare/v1.5.2...v1.5.3
[1.5.2]: https://github.com/Automattic/jetpack-logo/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/Automattic/jetpack-logo/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Automattic/jetpack-logo/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Automattic/jetpack-logo/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Automattic/jetpack-logo/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Automattic/jetpack-logo/compare/v1.1.4...v1.2.0
[1.1.4]: https://github.com/Automattic/jetpack-logo/compare/v1.1.2...v1.1.4
[1.1.2]: https://github.com/Automattic/jetpack-logo/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Automattic/jetpack-logo/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Automattic/jetpack-logo/compare/v1.0.0...v1.1.0
