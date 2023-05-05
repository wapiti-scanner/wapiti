# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.15.2] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.15.1] - 2023-03-28
### Changed
- Minor internal updates.

## [1.15.0] - 2023-03-27
### Added
- Initialize yoast promo package in jetpack plugin [#29641]

## [1.14.0] - 2023-02-20
### Added
- Added the Import package. [#28824]

## [1.13.0] - 2023-01-02
### Added
- Blaze package: Add config initialization, initialization checks for loading. [#28077]

## [1.12.0] - 2022-12-12
### Added
- Config: add option to init stats-admin [#27565]

## [1.11.1] - 2022-11-22
### Changed
- Updated package dependencies. [#27043]

## [1.11.0] - 2022-10-11
### Changed
- Integrate Stats package in Jetpack plugin [#26640]

## [1.10.0] - 2022-09-27
### Added
- Social: Added the option to configure if the plan information should be refreshed as the package is enabled. [#26294]

## [1.9.6] - 2022-08-26
### Changed
- Call ensure_options_$feature methods before the initialization

## [1.9.5] - 2022-08-23
### Changed
- Initialize VideoPress admin UI from the package [#25692]

## [1.9.4] - 2022-08-09
### Changed
- Initialize VideoPress package from the Config pkg [#25385]

## [1.9.3] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [1.9.2] - 2022-06-29

- Updated package dependencies.

## [1.9.1] - 2022-06-21
### Changed
- Renaming master to trunk.

## [1.9.0] - 2022-05-18
### Added
- Configuration for waf package [#24153]

## [1.8.0] - 2022-04-26
### Added
- Added the publicize package to be configured via the config package.

### Changed
- Updated package dependencies.

## [1.7.2] - 2022-04-19
### Added
- Enable WordAds from Config class

## [1.7.1] - 2022-04-06
### Removed
- Removed tracking dependency.

## [1.7.0] - 2022-03-23
### Added
- Search: added search initialization

## [1.6.1] - 2022-02-09
### Added
- Allow sync package consumers to provide custom data settings.

## [1.6.0] - 2022-01-04
### Added
- Accept options for the IDC package.

### Changed
- Updated package textdomain from `jetpack` to `jetpack-config`.

## [1.5.4] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.5.3] - 2021-10-13
### Changed
- Updated package dependencies.

## [1.5.2] - 2021-10-12
### Added
- Add support for the identity-crisis package

## [1.5.1] - 2021-09-28
### Changed
- Updated package dependencies.

## [1.5.0] - 2021-09-22
### Added
- Allow for enabling and initializing new Post_List package from Config package.

## [1.4.7] - 2021-08-31
### Changed
- updates annotations versions.

## [1.4.6] - 2021-05-25
### Changed
- Updated package dependencies.

## [1.4.5] - 2021-04-27
### Changed
- Updated package dependencies.

## [1.4.4] - 2021-03-30
### Added
- Composer alias for dev-master, to improve dependencies

### Changed
- Update package dependencies.

## [1.4.3] - 2021-01-19

- Add mirror-repo information to all current composer packages
- Monorepo: Reorganize all projects

## [1.4.2] - 2020-10-28

- Updated PHPCS: Packages and Debugger
- Config: remove tos and tracking features
- Config: add info about the package dependencies to the package docs

## [1.4.1] - 2020-09-15

- Config: remove tos and tracking features

## [1.4.0] - 2020-08-26

- Config: Remove composer dependencies
- Config: Add connection status check

## [1.3.0] - 2020-06-26

- Config: check for both JITM namespaces

## [1.2.0] - 2020-05-20

- Store the list of active plugins that uses connection in an option
- Implement pre-connection JITMs
- Connection Package: Handle disconnections gracefully

## [1.1.0] - 2020-01-23

- Moved JITM initialization to plugins_loaded.

## [1.0.1] - 2020-01-20

- Move connection manager related logic to after plugins_loaded.

## 1.0.0 - 2020-01-14

- Trying to add deterministic initialization.

[1.15.2]: https://github.com/Automattic/jetpack-config/compare/v1.15.1...v1.15.2
[1.15.1]: https://github.com/Automattic/jetpack-config/compare/v1.15.0...v1.15.1
[1.15.0]: https://github.com/Automattic/jetpack-config/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/Automattic/jetpack-config/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/Automattic/jetpack-config/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/Automattic/jetpack-config/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/Automattic/jetpack-config/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/Automattic/jetpack-config/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/Automattic/jetpack-config/compare/v1.9.6...v1.10.0
[1.9.6]: https://github.com/Automattic/jetpack-config/compare/v1.9.5...v1.9.6
[1.9.5]: https://github.com/Automattic/jetpack-config/compare/v1.9.4...v1.9.5
[1.9.4]: https://github.com/Automattic/jetpack-config/compare/v1.9.3...v1.9.4
[1.9.3]: https://github.com/Automattic/jetpack-config/compare/v1.9.2...v1.9.3
[1.9.2]: https://github.com/Automattic/jetpack-config/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/Automattic/jetpack-config/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/Automattic/jetpack-config/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/Automattic/jetpack-config/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/Automattic/jetpack-config/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-config/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-config/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/Automattic/jetpack-config/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-config/compare/v1.5.4...v1.6.0
[1.5.4]: https://github.com/Automattic/jetpack-config/compare/v1.5.3...v1.5.4
[1.5.3]: https://github.com/Automattic/jetpack-config/compare/v1.5.2...v1.5.3
[1.5.2]: https://github.com/Automattic/jetpack-config/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/Automattic/jetpack-config/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Automattic/jetpack-config/compare/v1.4.7...v1.5.0
[1.4.7]: https://github.com/Automattic/jetpack-config/compare/v1.4.6...v1.4.7
[1.4.6]: https://github.com/Automattic/jetpack-config/compare/v1.4.5...v1.4.6
[1.4.5]: https://github.com/Automattic/jetpack-config/compare/v1.4.4...v1.4.5
[1.4.4]: https://github.com/Automattic/jetpack-config/compare/v1.4.3...v1.4.4
[1.4.3]: https://github.com/Automattic/jetpack-config/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/Automattic/jetpack-config/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/Automattic/jetpack-config/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/Automattic/jetpack-config/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Automattic/jetpack-config/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Automattic/jetpack-config/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Automattic/jetpack-config/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/Automattic/jetpack-config/compare/v1.0.0...v1.0.1
