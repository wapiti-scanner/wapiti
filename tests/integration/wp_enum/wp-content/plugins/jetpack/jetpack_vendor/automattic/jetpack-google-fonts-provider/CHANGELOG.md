# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [0.5.1] - 2023-02-20
### Changed
- Minor internal updates.

## [0.5.0] - 2023-01-30
### Added
- Add support for new WP Fonts API in Google Fonts provider. [#28054]

## [0.4.2] - 2023-01-26
### Changed
- Minor internal updates.

## [0.4.1] - 2023-01-17
### Fixed
- Use `wp_get_global_styles()` and fallback to `gutenberg_get_global_styles()` since the latter was removed from Gutenberg. [#28411]

## [0.4.0] - 2022-12-12
### Added
- Added a way to filter the Google Fonts API url [#27719]

## [0.3.6] - 2022-12-06
### Changed
- Updated package dependencies. [#27688]

## [0.3.5] - 2022-11-28
### Changed
- Updated package dependencies. [#27043]

## [0.3.4] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [0.3.3] - 2022-07-12
### Changed
- Updated package dependencies.

## [0.3.2] - 2022-06-21
### Changed
- Renaming `master` references to `trunk` [#24712]

## [0.3.1] - 2022-06-14

## [0.3.0] - 2022-04-26
### Added
- Add functions for enqueueing fonts used in block and global style settings

### Changed
- Updated package dependencies.
- Update package.json metadata.

## [0.2.2] - 2022-04-06
### Added
- Set composer package type to "jetpack-library" so i18n will work.

## [0.2.1] - 2022-03-29
### Added
- Set composer package type to "jetpack-library" so i18n will work.

## [0.2.0] - 2022-03-15
### Changed
- Updated package dependencies

### Deprecated
- Google Fonts: update the method used to preconnect Fonts source domain.

## 0.1.0 - 2022-03-08
### Added
- Adds a provider for Google Fonts using the new Webfonts API in Gutenberg

[0.5.2]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.3.6...v0.4.0
[0.3.6]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Automattic/jetpack-google-fonts-provider/compare/v0.1.0...v0.2.0
