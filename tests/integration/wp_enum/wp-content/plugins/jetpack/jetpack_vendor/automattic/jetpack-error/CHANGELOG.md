# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.20] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.3.19] - 2023-02-20
### Changed
- Minor internal updates.

## [1.3.18] - 2022-12-06
### Changed
- Updated package dependencies. [#27688]

## [1.3.17] - 2022-11-28
### Changed
- Updated package dependencies. [#27043]

## [1.3.16] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [1.3.15] - 2022-06-21
### Changed
- Renaming master to trunk. [#24661]

## [1.3.14] - 2022-04-26
### Changed
- Updated package dependencies.

## [1.3.13] - 2022-01-25
### Changed
- Updated package dependencies.

## [1.3.12] - 2022-01-04
### Changed
- Switch to pcov for code coverage.
- Updated package dependencies

## [1.3.11] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.3.10] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [1.3.9] - 2021-10-19
### Changed
- Updated package dependencies.

## [1.3.8] - 2021-10-12
### Changed
- Updated package dependencies

## [1.3.7] - 2021-09-28
### Changed
- Updated package dependencies.

## [1.3.6] - 2021-08-31
### Changed
- Run composer update on test-php command instead of phpunit.
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).

## [1.3.5] - 2021-05-25
### Changed
- Updated package dependencies.

## [1.3.4] - 2021-04-27
### Changed
- Updated package dependencies.

## [1.3.3] - 2021-03-30
### Added
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

## [1.3.0] - 2020-12-07

- Pin dependencies
- Packages: Update for PHP 8 testing

## [1.2.0] - 2020-08-13

- CI: Try collect js coverage

## [1.1.0] - 2020-06-22

- PHPCS: Clean up the packages

## [1.0.4] - 2019-11-08

- Packages: Use classmap instead of PSR-4

## [1.0.2] - 2019-10-28

- Packages: Add gitattributes files to all packages that need th…

## [1.0.1] - 2019-09-20

- Docs: Unify usage of @package phpdoc tags

## 1.0.0 - 2019-09-14

- Packages: Introduce a jetpack-error package

[1.3.20]: https://github.com/Automattic/jetpack-error/compare/v1.3.19...v1.3.20
[1.3.19]: https://github.com/Automattic/jetpack-error/compare/v1.3.18...v1.3.19
[1.3.18]: https://github.com/Automattic/jetpack-error/compare/v1.3.17...v1.3.18
[1.3.17]: https://github.com/Automattic/jetpack-error/compare/v1.3.16...v1.3.17
[1.3.16]: https://github.com/Automattic/jetpack-error/compare/v1.3.15...v1.3.16
[1.3.15]: https://github.com/Automattic/jetpack-error/compare/v1.3.14...v1.3.15
[1.3.14]: https://github.com/Automattic/jetpack-error/compare/v1.3.13...v1.3.14
[1.3.13]: https://github.com/Automattic/jetpack-error/compare/v1.3.12...v1.3.13
[1.3.12]: https://github.com/Automattic/jetpack-error/compare/v1.3.11...v1.3.12
[1.3.11]: https://github.com/Automattic/jetpack-error/compare/v1.3.10...v1.3.11
[1.3.10]: https://github.com/Automattic/jetpack-error/compare/v1.3.9...v1.3.10
[1.3.9]: https://github.com/Automattic/jetpack-error/compare/v1.3.8...v1.3.9
[1.3.8]: https://github.com/Automattic/jetpack-error/compare/v1.3.7...v1.3.8
[1.3.7]: https://github.com/Automattic/jetpack-error/compare/v1.3.6...v1.3.7
[1.3.6]: https://github.com/Automattic/jetpack-error/compare/v1.3.5...v1.3.6
[1.3.5]: https://github.com/Automattic/jetpack-error/compare/v1.3.4...v1.3.5
[1.3.4]: https://github.com/Automattic/jetpack-error/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/Automattic/jetpack-error/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/Automattic/jetpack-error/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/Automattic/jetpack-error/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Automattic/jetpack-error/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Automattic/jetpack-error/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Automattic/jetpack-error/compare/v1.0.4...v1.1.0
[1.0.4]: https://github.com/Automattic/jetpack-error/compare/v1.0.2...v1.0.4
[1.0.2]: https://github.com/Automattic/jetpack-error/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Automattic/jetpack-error/compare/v1.0.0...v1.0.1
