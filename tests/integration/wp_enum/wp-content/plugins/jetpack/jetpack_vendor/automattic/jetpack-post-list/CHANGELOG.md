# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.5] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [0.4.4] - 2023-02-20
### Changed
- Minor internal updates.

## [0.4.3] - 2022-12-06
### Changed
- Updated package dependencies. [#27688]

## [0.4.2] - 2022-11-28
### Changed
- Updated package dependencies. [#27043]

## [0.4.1] - 2022-09-20
### Changed
- Updated package dependencies.

## [0.4.0] - 2022-08-30
### Changed
- Rebrand Publicize to Jetpack Social [#25787]
- Updated package dependencies. [#25158]

## [0.3.1] - 2022-07-06
### Changed
- PHPCS: fix `WordPress.Security.ValidatedSanitizedInput`. [#23942]
- Renaming master to trunk. [#24661]
- Updated package dependencies. [#24045]

## [0.3.0] - 2022-02-01
### Changed
- Build: remove unneeded files from production build.
- Switch to pcov for code coverage.
- Updated package dependencies.
- Updated package textdomain from `jetpack` to `jetpack-post-list`.

## [0.2.4] - 2021-11-19
### Fixed
- Fixed the stretched thumbnails when using a non-square image.
- Fixed the broken layout after making a quick edit.

### Changed
- Updated package dependencies

## [0.2.3] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Thumbnails only available on "Pages" and "Posts". Share action only when publicize and block-editor supported.
- Updated package dependencies.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [0.2.2] - 2021-10-08
### Fixed
- Fixed the check for a valid thumbnail

## [0.2.1] - 2021-10-06
### Changed
- Updated package dependencies

## [0.2.0] - 2021-10-06
### Added
- Added a 'Share' post action

### Changed
- Only add the thumbnail column for post types that support it
- Updated package dependencies.

## 0.1.0 - 2021-09-22
### Added
- Add the new Post List package to Jetpack project

### Changed
- Updated the default columns displayed on the post and page list screens
- Refactored thumbnail preview to function server side. All javascript removed.

[0.4.5]: https://github.com/automattic/jetpack-post-list/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/automattic/jetpack-post-list/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/automattic/jetpack-post-list/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/automattic/jetpack-post-list/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/automattic/jetpack-post-list/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/automattic/jetpack-post-list/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/automattic/jetpack-post-list/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/automattic/jetpack-post-list/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/automattic/jetpack-post-list/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/automattic/jetpack-post-list/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/automattic/jetpack-post-list/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/automattic/jetpack-post-list/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/automattic/jetpack-post-list/compare/v0.1.0...v0.2.0
