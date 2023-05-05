# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.11] - 2023-05-01
### Changed
- Internal updates.

## [0.5.10] - 2023-04-17
### Changed
- Updated package dependencies. [#30019]

## [0.5.9] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [0.5.8] - 2023-04-04
### Changed
- Updated package dependencies. [#29854]

## [0.5.7] - 2023-04-03
### Changed
- Internal updates.

## [0.5.6] - 2023-03-20
### Changed
- Updated package dependencies. [#29471]

## [0.5.5] - 2023-03-08
### Changed
- Updated package dependencies. [#29216]

## [0.5.4] - 2023-02-20
### Changed
- Minor internal updates.

## [0.5.3] - 2023-02-15
### Changed
- Update to React 18. [#28710]

### Fixed
- Blaze: prevent fatals on frontend-loaded Gutenberg + bail early if Jetpack is not connected [#28955]
- Do not load the Blaze script in the classic editor. [#28900]

## [0.5.2] - 2023-02-08
### Changed
- Only display the Blaze UI to admins on a site. [#28748]
- Updated package dependencies. [#28682]

### Fixed
- Do not display "Blaze" links in the post list for password-protected posts. [#28747]

## [0.5.1] - 2023-02-02
### Added
- Display "Blaze" links in page list too. [#28715]

### Changed
- Do not require Jetpack's JSON API module to use feature. [#28672]

### Fixed
- Do not display Blaze links in non-supported CPT pages. [#28671]

## [0.5.0] - 2023-01-26
### Changed
- Move away from Singleton pattern to improve performance [#28587]

### Fixed
- Avoid unnecessary requests for eligibility [#28568]

## [0.4.0] - 2023-01-23
### Added
- Add new method to request eligibility to Blaze from WordPress.com. [#28353]
- Add tracking when the post-publish panel is displayed. [#28392]

### Changed
- Start using utilities from Status package to detect whether a site is private or "coming-soon" (unlaunched). [#28328]

### Fixed
- Always enqueue Jetpack Connnection info when enqueuing Blaze script [#28457]

## [0.3.4] - 2023-01-16
### Added
- Do not display the Blaze UI on private or unlaunched sites. [#28315]

### Changed
- Do not load the Blaze UI if the JSON API module is inactive. [#28267]
- Only display the Blaze UI if the connected user's language is English. [#28266]

## [0.3.3] - 2023-01-11
### Changed
- Updated package dependencies. [#28127]

### Fixed
- Do not load the Blaze panel in the site editor or the widget editor. [#28187]

## [0.3.2] - 2023-01-04
### Changed
- Editor panel: update Blaze icon and wording. [#28155]
- Post List link: only display UI on WordPress.com Simple and WoA sites for now. [#28155]
- Update wording in Post List link. [#28155]

## [0.3.1] - 2023-01-03
### Fixed
- Blaze: Only show post row action to promote if the post is published. [#28139]

## [0.3.0] - 2023-01-02
### Added
- Blaze package: Add config initialization, initialization checks for loading. [#28077]

## [0.2.0] - 2022-12-27
### Added
- Add new Post-publish panel in the block editor [#28073]

## 0.1.0 - 2022-12-19
### Changed
- Updated package dependencies. [#27906]

[0.5.11]: https://github.com/automattic/jetpack-blaze/compare/v0.5.10...v0.5.11
[0.5.10]: https://github.com/automattic/jetpack-blaze/compare/v0.5.9...v0.5.10
[0.5.9]: https://github.com/automattic/jetpack-blaze/compare/v0.5.8...v0.5.9
[0.5.8]: https://github.com/automattic/jetpack-blaze/compare/v0.5.7...v0.5.8
[0.5.7]: https://github.com/automattic/jetpack-blaze/compare/v0.5.6...v0.5.7
[0.5.6]: https://github.com/automattic/jetpack-blaze/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/automattic/jetpack-blaze/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/automattic/jetpack-blaze/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/automattic/jetpack-blaze/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/automattic/jetpack-blaze/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/automattic/jetpack-blaze/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/automattic/jetpack-blaze/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/automattic/jetpack-blaze/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/automattic/jetpack-blaze/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/automattic/jetpack-blaze/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/automattic/jetpack-blaze/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/automattic/jetpack-blaze/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/automattic/jetpack-blaze/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/automattic/jetpack-blaze/compare/v0.1.0...v0.2.0
