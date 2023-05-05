# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.2] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [0.6.1] - 2023-04-05
### Bug fixes
- Assets: avoid fatal error with outdated package versions. [#29947]

## [0.6.0] - 2023-04-04
### Changed
- Use core WordPress methods to add the Tracking pixel to the page, instead of printing the tracking pixel directly. [#29780]

### Deprecated
- Methods used to retrieve tracking pixels are now deprecated. No replacement needed, we now hook / enqueue the tracking pixels using core WP methods. [#29780]

## [0.5.2] - 2023-03-20
### Changed
- Updated package dependencies. [#29480]

## [0.5.1] - 2023-02-20
### Changed
- Minor internal updates.

## [0.5.0] - 2023-02-15
### Added
- Added new options to store the timestamp when Odyssey is enabled and disabled [#28794]
- Stats: Adds support for Notice control [#28857]

## [0.4.2] - 2023-02-08
### Changed
- Minor internal updates.

## [0.4.1] - 2023-01-11
### Changed
- Updated package dependencies.

## [0.4.0] - 2022-12-06
### Added
- Stats: added streak, highlights, insights for WPCOM_Stats [#27604]

### Changed
- Updated package dependencies. [#27688]

## [0.3.3] - 2022-11-28
### Changed
- Updated package dependencies. [#27043]

## [0.3.2] - 2022-11-07
### Changed
- Updated package dependencies. [#27278]

## [0.3.1] - 2022-10-25
### Changed
- Updated package dependencies. [#26705]

## [0.3.0] - 2022-10-19
### Changed
- Cache errors when fetching stats and reverted cache prefix. [#26922]

## [0.2.0] - 2022-10-13
### Changed
- Changed cache prefix [#26719]
- Updated readme for Stats package [#26759]

## 0.1.0 - 2022-10-11
### Added
- Stats: Add package scaffold [#26312]
- Stats package: Add 'jetpack.getBlog' XMLRPC endpoint [#26473]
- Stats package: Add entrypoint class for setting hooks and configuration. [#26601]
- Stats package: Introduce WPCOM_Stats class [#26530]
- Stats package: Manage Stats options [#26431]
- Stats Package: Tracking Pixel functionality [#26516]

### Changed
- Add mirror repo [#26750]

### Fixed
- Fixing static method which was called without self reference. [#26640]

[0.6.2]: https://github.com/Automattic/jetpack-stats/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Automattic/jetpack-stats/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Automattic/jetpack-stats/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/Automattic/jetpack-stats/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Automattic/jetpack-stats/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Automattic/jetpack-stats/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/Automattic/jetpack-stats/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Automattic/jetpack-stats/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Automattic/jetpack-stats/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/Automattic/jetpack-stats/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Automattic/jetpack-stats/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Automattic/jetpack-stats/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Automattic/jetpack-stats/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Automattic/jetpack-stats/compare/v0.1.0...v0.2.0
