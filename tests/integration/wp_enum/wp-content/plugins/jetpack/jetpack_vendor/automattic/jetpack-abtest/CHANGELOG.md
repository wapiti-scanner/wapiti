# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.10.13] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.10.12] - 2023-02-20
### Changed
- Minor internal updates.

## [1.10.11] - 2022-12-06
### Changed
- Updated package dependencies. [#27688]

## [1.10.10] - 2022-11-28
### Changed
- Updated package dependencies. [#27043]

## [1.10.9] - 2022-10-25
### Changed
- Updated package dependencies. [#26705]

## [1.10.8] - 2022-09-20
### Changed
- Updated package dependencies.

## [1.10.7] - 2022-09-08
### Changed
- Updated package dependencies.

## [1.10.6] - 2022-08-30
### Changed
- Updated package dependencies. [#25694]

## [1.10.5] - 2022-08-23
### Changed
- Updated package dependencies. [#25628]

## [1.10.4] - 2022-08-03
### Changed
- Updated package dependencies. [#25300, #25315]

## [1.10.3] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [1.10.2] - 2022-06-21
### Changed
- Renaming master to trunk. [#24661]

## [1.10.1] - 2022-06-14
### Changed
- Updated package dependencies. [#24529]

## [1.10.0] - 2022-05-04
### Changed
- Updated package dependencies. [#24095]

## [1.9.23] - 2022-04-26
### Changed
- Updated package dependencies.

## [1.9.22] - 2022-04-19
### Changed
- Updated package dependencies.

## [1.9.21] - 2022-03-02
### Changed
- Updated package dependencies.

## [1.9.20] - 2022-01-25
### Changed
- Updated package dependencies.

## [1.9.19] - 2022-01-18
### Changed
- Updated package dependencies.

## [1.9.18] - 2022-01-04
### Changed
- Switch to pcov for code coverage.
- Updated package dependencies

## [1.9.17] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.9.16] - 2021-11-30
### Changed
- Updated package dependencies.

## [1.9.15] - 2021-11-23
### Changed
- Updated package dependencies.

## [1.9.14] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [1.9.13] - 2021-10-19
### Changed
- Updated package dependencies.

## [1.9.12] - 2021-10-12
### Changed
- Updated package dependencies

## [1.9.11] - 2021-09-28
### Changed
- Updated package dependencies.

## [1.9.10] - 2021-08-31
### Changed
- Run composer update on test-php command instead of phpunit
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).

## [1.9.9] - 2021-07-27
### Changed
- Updated package dependencies.

## [1.9.8] - 2021-06-29
### Changed
- Updated package dependencies.

## [1.9.7] - 2021-05-25
### Changed
- Updated package dependencies.

## [1.9.6] - 2021-04-27
### Changed
- Updated package dependencies.

## [1.9.5] - 2021-03-30
### Added
- Composer alias for dev-master, to improve dependencies

### Changed
- Update package dependencies.

### Fixed
- Use `composer update` rather than `install` in scripts, as composer.lock isn't checked in.

## [1.9.4] - 2021-02-23

- CI: Make tests more generic

## [1.9.3] - 2021-02-08

- Update dependencies to latest stable

## [1.9.2] - 2021-01-28

- Update dependencies to latest stable

## [1.9.1] - 2021-01-26

- Add mirror-repo information to all current composer packages
- Monorepo: Reorganize all projects

## [1.9.0] - 2021-01-05

- Coverage Update whitelist for backend tests
- Pin dependencies
- Packages: Update for PHP 8 testing
- Tests:  Try CodeCov coverage app
- Add .gitignore to export-ignore for dist releases

## [1.8.4] - 2020-11-24

- Version packages for release

## [1.8.3] - 2020-11-24

- Fix remaining phpcs warnings in most of requirelist
- Updated PHPCS: Packages and Debugger

## [1.8.2] - 2020-11-05

- Update dependencies to latest stable

## [1.8.1] - 2020-10-29

- Update dependencies to latest stable

## [1.8.0] - 2020-10-27

- Updated dependencies to latest stable

## [1.7.4] - 2020-10-14

- Update dependencies to latest stable

## [1.7.3] - 2020-10-09

- Update dependencies to latest stable

## [1.7.2] - 2020-10-06

- Update dependencies to latest stable

## [1.7.1] - 2020-10-01

- Update dependencies to latest stable

## [1.7.0] - 2020-09-29

- Update dependencies to latest stable

## [1.6.1] - 2020-09-09

- Update dependencies to latest stable

## [1.6.0] - 2020-08-26

- CI: Try collect js coverage
- Docker: Add package testing shortcut

## [1.5.2] - 2020-08-10

- Update dependencies to latest stable

## [1.5.1] - 2020-08-10

- Update dependencies to latest stable

## [1.5.0] - 2020-07-28

- Package Unit tests: update test file names to make sure they runs in Travis

## [1.4.2] - 2020-07-06

- Update dependencies to latest stable

## [1.4.1] - 2020-07-01

- Update dependencies to latest stable

## [1.4.0] - 2020-06-30

- PHPCS: Clean up the packages
- PHPCS Updates after WPCS 2.3

## [1.3.1] - 2020-06-01

- Update dependencies to latest stable

## [1.3.0] - 2020-05-26

- Update dependencies to latest stable

## [1.2.0] - 2020-04-28

- Update dependencies to latest stable

## [1.1.0] - 2020-03-31

- Update dependencies to latest stable

## [1.0.4] - 2019-12-04

## [1.0.3] - 2019-12-04

- Updating dependencies for 'abtest'

## [1.0.2] - 2019-11-08

- Packages: Use classmap instead of PSR-4

## [1.0.1] - 2019-10-28

- Packages: Add gitattributes files to all packages that need th…

## 1.0.0 - 2019-09-14

- Packages: Introduce a simple A/B test package

[1.10.13]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.12...v1.10.13
[1.10.12]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.11...v1.10.12
[1.10.11]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.10...v1.10.11
[1.10.10]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.9...v1.10.10
[1.10.9]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.8...v1.10.9
[1.10.8]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.7...v1.10.8
[1.10.7]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.6...v1.10.7
[1.10.6]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.5...v1.10.6
[1.10.5]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.4...v1.10.5
[1.10.4]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.3...v1.10.4
[1.10.3]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.2...v1.10.3
[1.10.2]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.23...v1.10.0
[1.9.23]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.22...v1.9.23
[1.9.22]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.21...v1.9.22
[1.9.21]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.20...v1.9.21
[1.9.20]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.19...v1.9.20
[1.9.19]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.18...v1.9.19
[1.9.18]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.17...v1.9.18
[1.9.17]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.16...v1.9.17
[1.9.16]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.15...v1.9.16
[1.9.15]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.14...v1.9.15
[1.9.14]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.13...v1.9.14
[1.9.13]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.12...v1.9.13
[1.9.12]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.11...v1.9.12
[1.9.11]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.10...v1.9.11
[1.9.10]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.9...v1.9.10
[1.9.9]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.8...v1.9.9
[1.9.8]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.7...v1.9.8
[1.9.7]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.6...v1.9.7
[1.9.6]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.5...v1.9.6
[1.9.5]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.4...v1.9.5
[1.9.4]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.3...v1.9.4
[1.9.3]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.2...v1.9.3
[1.9.2]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.8.4...v1.9.0
[1.8.4]: https://github.com/Automattic/jetpack-abtest/compare/v1.8.3...v1.8.4
[1.8.3]: https://github.com/Automattic/jetpack-abtest/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/Automattic/jetpack-abtest/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.7.4...v1.8.0
[1.7.4]: https://github.com/Automattic/jetpack-abtest/compare/v1.7.3...v1.7.4
[1.7.3]: https://github.com/Automattic/jetpack-abtest/compare/v1.7.2...v1.7.3
[1.7.2]: https://github.com/Automattic/jetpack-abtest/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.5.2...v1.6.0
[1.5.2]: https://github.com/Automattic/jetpack-abtest/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.4.2...v1.5.0
[1.4.2]: https://github.com/Automattic/jetpack-abtest/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Automattic/jetpack-abtest/compare/v1.0.4...v1.1.0
[1.0.4]: https://github.com/Automattic/jetpack-abtest/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Automattic/jetpack-abtest/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Automattic/jetpack-abtest/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Automattic/jetpack-abtest/compare/v1.0.0...v1.0.1
