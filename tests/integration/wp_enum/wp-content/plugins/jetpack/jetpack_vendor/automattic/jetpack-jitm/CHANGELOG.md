# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.6] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [2.3.5] - 2023-04-04
### Added
- Add external link icons in JITM [#29654]

### Changed
- Updated package dependencies. [#29854]

## [2.3.4] - 2023-03-28
### Fixed
- JITM: Fix button overflow when text length is too big [#29749]

## [2.3.3] - 2023-03-27
### Changed
- JITM: Update styles [#29709]

## [2.3.2] - 2023-03-20
### Changed
- Updated package dependencies. [#29471]

## [2.3.1] - 2023-03-08
### Changed
- Updated package dependencies. [#29216]

## [2.3.0] - 2023-02-20
### Changed
- Moving deleting connection owner notice from JITM to Connection package. [#28516]

## [2.2.42] - 2023-02-15
### Changed
- Update to React 18. [#28710]

## [2.2.41] - 2023-02-06
### Fixed
- JITM: minor fix for styles on Safari browser.

## [2.2.40] - 2023-01-30
### Changed
- Updated styles for Just in Time Messages (notices) [#27515]

## [2.2.39] - 2023-01-25
### Changed
- Minor internal updates.

## [2.2.38] - 2023-01-23
### Fixed
- Prevent the activation page from displaying the JP License Activation JITM. [#27959]

## [2.2.37] - 2023-01-11
### Changed
- Updated package dependencies.

## [2.2.36] - 2022-12-27
### Removed
- Remove src/js files from final bundle [#27930]

## [2.2.35] - 2022-12-02
### Changed
- Updated package dependencies. [#27696]

## [2.2.34] - 2022-11-22
### Changed
- Updated package dependencies. [#27043]

## [2.2.33] - 2022-11-08
### Changed
- Updated package dependencies. [#27289]

## [2.2.32] - 2022-11-07
### Changed
- Updated package dependencies. [#27278]

## [2.2.31] - 2022-11-01
### Changed
- Updated package dependencies. [#27196]

## [2.2.30] - 2022-10-25
### Changed
- Updated package dependencies. [#26705]

## [2.2.29] - 2022-10-13
### Changed
- Updated package dependencies. [#26791]

## [2.2.28] - 2022-10-05
### Changed
- Updated package dependencies. [#26568]

## [2.2.27] - 2022-09-08
### Changed
- Updated package dependencies.

## [2.2.26] - 2022-08-29
### Changed
- Updated package dependencies.

## [2.2.25] - 2022-08-25
### Changed
- Updated package dependencies. [#25814]

## [2.2.24] - 2022-08-23
### Added
- Add custom styling rules for the JITMs displayed in My Jetpack. [#22452]
- Updated JITM readme. [#25739]

### Changed
- Updated package dependencies. [#25628]

## [2.2.23] - 2022-08-03
### Changed
- Updated package dependencies. [#25300, #25315]

## [2.2.22] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

## [2.2.21] - 2022-07-12
### Changed
- Updated package dependencies.

## [2.2.20] - 2022-06-21
### Changed
- Renaming master to trunk. [#24661]

## [2.2.19] - 2022-06-14
### Changed
- Updated package dependencies. [#24529]

## [2.2.18] - 2022-06-08
### Changed
- Reorder JS imports for `import/order` eslint rule. [#24601]

## [2.2.17] - 2022-05-18
### Changed
- Updated package dependencies [#24372]

## [2.2.16] - 2022-05-10
### Changed
- Updated package dependencies. [#24302]

## [2.2.15] - 2022-05-04
### Changed
- Remove use of `pnpx` in preparation for pnpm 7.0. [#24210]
- Updated package dependencies. [#24095]

### Deprecated
- Moved the options class into Connection. [#24095]

## [2.2.14] - 2022-04-26
### Changed
- Updated package dependencies.
- Update package.json metadata.

## [2.2.13] - 2022-04-19
### Changed
- PHPCS: Fix `WordPress.Security.ValidatedSanitizedInput`

## [2.2.12] - 2022-04-12
### Changed
- Updated package dependencies.

## [2.2.11] - 2022-04-06
### Changed
- Updated package dependencies

### Removed
- Removed tracking dependency.

## [2.2.10] - 2022-03-29
### Changed
- Updated package dependencies.

## [2.2.9] - 2022-03-23
### Changed
- Updated package dependencies.

## [2.2.8] - 2022-03-02
### Changed
- Updated package dependencies

## [2.2.7] - 2022-02-22
### Changed
- Updated package dependencies.

## [2.2.6] - 2022-02-16
### Changed
- Updated package dependencies.

## [2.2.5] - 2022-02-09
### Changed
- Updated package dependencies.

## [2.2.4] - 2022-02-02
### Changed
- Build: remove unneeded files from production build.
- Update use of old jQuery interfaces

## [2.2.3] - 2022-01-25
### Changed
- Updated package dependencies.

## [2.2.2] - 2022-01-18
### Changed
- General: update required node version to v16.13.2

## [2.2.1] - 2022-01-11
### Changed
- Updated package dependencies.

## [2.2.0] - 2022-01-04
### Changed
- Switch to pcov for code coverage.
- Updated package dependencies.
- Updated package textdomain from `jetpack` to `jetpack-jitm`.

## [2.1.1] - 2021-12-14
### Changed
- Updated package dependencies.

## [2.1.0] - 2021-11-30
### Added
- Add proper JS and CSS builder.
- Adds filters to allow sideloading of the Jetpack Backup plugin through JITMs.
- JITM: Added ability to sideload Jetpack Boost plugin.

### Changed
- Add `output.filename` in Webpack config to override changed default.
- Colors: update Jetpack Primary color to match latest brand book.

### Fixed
- JITM: wrap CTA below text on small viewports

## [2.0.8] - 2021-11-23
### Changed
- Updated package dependencies.

## [2.0.7] - 2021-11-16
### Added
- Use monorepo `validate-es` script to validate Webpack builds.

### Changed
- Updated package dependencies.

## [2.0.6] - 2021-11-09
### Changed
- Update webpack build config.

## [2.0.5] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [2.0.4] - 2021-10-26
### Changed
- Updated package dependencies.

## [2.0.3] - 2021-10-19
### Changed
- Updated package dependencies.

## [2.0.2] - 2021-10-12
### Changed
- Updated package dependencies

## [2.0.1] - 2021-09-28
### Changed
- Allow Node ^14.17.6 to be used in this project. This shouldn't change the behavior of the code itself.
- Updated package dependencies.

## [2.0.0] - 2021-08-31
### Changed
- Run composer update on test-php command instead of phpunit.
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).
- Update annotations versions.
- Updated package dependencies.
- Update to latest webpack, webpack-cli and calypso-build.
- Upgrade to Webpack 5.
- Use Node 16.7.0 in tooling.

### Removed
- Removed IE11 support.

## [1.16.2] - 2021-07-27
### Changed
- Updated package dependencies.

## [1.16.1] - 2021-06-29
### Changed
- Update package dependencies.
- Update node version requirement to 14.16.1
- Update the usage of Redirect lib and passes the unlinked param as a query argument.

## [1.16.0] - 2021-05-25
### Added
- JITM: allow the plugin to set the icon for pre-connection JITMs.
- JITM: move sync updated option hook to the JITM package.

### Changed
- JITM: prevent JITMs from being registered more than once.
- JITM: remove jetpack-constants dependency from composer.json
- JITM: set the default values of the jetpack_just_in_time_msgs and jetpack_just_in_time_msg_cache filters to true.
- JITM: Use an action instead of a property to prevent JITMs from being registered multiple times
- JITM: Use the Device_Detection package to determine if the device is mobile.
- Updated package dependencies
- update jetpack-redirect dependency

## [1.15.1] - 2021-05-03
### Changed
- JITM: Use manager::get_authorization_url to obtain the authorization url in the user deletion notice.

## [1.15.0] - 2021-04-27
### Added
- Move JITM's REST API endpoints into the package

### Changed
- Always display pre-connection JITMs, without the need to set a filter.
- Avoid wrapping text in the main CTA button.
- Bump JITM package version requirement.
- JITM: Update CTA redirect url with unlinked query arg to indicate current user is not connected.
- Update package dependencies.
- Use the a8c-mc-stats package to generate stats.

## [1.14.1] - 2021-03-30
### Added
- Composer alias for dev-master, to improve dependencies

### Changed
- Use is_connected instead of is_active to instantiate Pre/Post_Connection_JITM
- Add a jetpack_pre_connection_jitms filter.
- Update colors to match upcoming WP 5.7 color changes
- Update Node to match latest LTS 12
- Update package dependencies.

### Fixed
- Use `composer update` rather than `install` in scripts, as composer.lock isn't checked in.

## [1.14.0] - 2021-02-23

- Recommendations: Hide JITMs when banner is displaying
- Setup Wizard: Remove setup wizard
- JITM: move jetpack-jitm.js to the JITM package
- CI: Make tests more generic

## [1.13.5] - 2021-02-08

- Update dependencies to latest stable

## [1.13.4] - 2021-01-28

- Update dependencies to latest stable

## [1.13.3] - 2021-01-26

- Update dependencies to latest stable

## [1.13.2] - 2021-01-26

- Update dependencies to latest stable

## [1.13.1] - 2021-01-26

- Add mirror-repo information to all current composer packages
- Monorepo: Reorganize all projects

## [1.13.0] - 2021-01-05

- Update dependency brain/monkey to v2.6.0
- Pin dependencies
- Packages: Update for PHP 8 testing

## [1.12.2] - 2020-12-09

- Update dependencies to latest stable

## [1.12.1] - 2020-11-24

- Version packages for release

## [1.12.0] - 2020-11-24

- Status: Introduce get_site_suffix method
- General: update minimum required version to WordPress 5.5
- Updated PHPCS: Packages and Debugger

## [1.11.2] - 2020-11-05

- Update dependencies to latest stable

## [1.11.1] - 2020-10-29

- Update dependencies to latest stable

## [1.11.0] - 2020-10-27

- JITM: add a Pre_Connection_JITM::generate_admin_url method
- JITM: use is_active from the connection package
- JITM: regenerate assets

## [1.10.4] - 2020-10-14

- Update dependencies to latest stable

## [1.10.3] - 2020-10-09

- Update dependencies to latest stable

## [1.10.2] - 2020-10-06

- Update dependencies to latest stable

## [1.10.1] - 2020-10-01

- Update dependencies to latest stable

## [1.10.0] - 2020-09-29

- Update dependencies to latest stable

## [1.9.1] - 2020-09-09

- Update dependencies to latest stable

## [1.9.0] - 2020-08-26

- Compat: add new Creative Mail compat file
- Packages: Update filenames after #16810
- CI: Try collect js coverage
- Docker: Add package testing shortcut

## [1.8.2] - 2020-08-10

- Update dependencies to latest stable

## [1.8.1] - 2020-08-10

- Update dependencies to latest stable

## [1.8.0] - 2020-07-28

- Core Compat: Site Environment
- Core REST API: Add permission callback to delete_jitm_message endpoint

## [1.7.2] - 2020-07-06

- Update dependencies to latest stable

## [1.7.1] - 2020-07-01

- Update dependencies to latest stable

## [1.7.0] - 2020-06-30

- PHPCS: Clean up the packages
- Hide pre-connection JITM on the posts page when few posts are published
- Jetpack Setup Wizard: Do not show pre-connection JITMs to non admins
- JITM: change 'setup' to 'set up' in pre-connection JITMs
- Pre-connection JITMS: Link to connect-in-place flow
- JITM: add Redirect use statement

## [1.6.5] - 2020-06-01

- Hide pre-connection JITM on the posts page when few posts are published

## [1.6.4] - 2020-06-01

- Update dependencies to latest stable

## [1.6.3] - 2020-05-29

- Jetpack Setup Wizard: Do not show pre-connection JITMs to non admins

## [1.6.2] - 2020-05-29

- JITM: change 'setup' to 'set up' in pre-connection JITMs
- Pre-connection JITMS: Link to connect-in-place flow

## [1.6.1] - 2020-05-28

- JITM: add Redirect use statement

## [1.6.0] - 2020-05-26

- JITM: expand docs and tests to account for pre-connection messages
- Improve responsiveness of JITMs
- JITM: fix the use statements
- Implement pre-connection JITMs
- JITM: Allow JITM on stats pages

## [1.5.1] - 2020-04-30

- JITM: Allow JITM on stats pages

## [1.5.0] - 2020-04-28

- Use jp.com redirect in all links

## [1.4.0] - 2020-03-31

- Update dependencies to latest stable

## [1.3.0] - 2020-03-31

- Use dynamic Jetpack logos on JITMs

## [1.2.0] - 2020-02-25

- JITM: Show ToS update notice

## [1.1.2] - 2020-02-14

- SSO: do not display JITM when not in wp-admin

## [1.1.1] - 2020-01-23

- Moved JITM initialization to plugins_loaded.

## [1.1.0] - 2020-01-07

- Add partner subsidiary id to upgrade URLs.

## [1.0.10] - 2019-11-25

- Connection Owner Deletion Notice: Fix display bug and sanitize…

## [1.0.9] - 2019-11-19

- Don't show JITMs on Gutenberg editor pages (for now)

## [1.0.8] - 2019-11-08

- Packages: Use classmap instead of PSR-4

## [1.0.7] - 2019-11-08

- Remove unused get_emblem method

## [1.0.6] - 2019-10-31

- Inherit 400 weight for button fonts

## [1.0.5] - 2019-10-28

- PHPCS: JITM and Assets packages

## [1.0.4] - 2019-10-24

- Update Jetpack button and card styles to match WordPress 5.3

## [1.0.3] - 2019-10-23

- Use spread operator instead of func_get_args

## [1.0.2] - 2019-10-17

- Change the class in the add_filter() calls to $this. Also fix some

## [1.0.1] - 2019-09-27

- Initial trial of prefer-dist
- JITM: Send the user's role in the request for JITM messages

## 1.0.0 - 2019-09-14

- Update Jetpack to use new JITM package

[2.3.6]: https://github.com/Automattic/jetpack-jitm/compare/v2.3.5...v2.3.6
[2.3.5]: https://github.com/Automattic/jetpack-jitm/compare/v2.3.4...v2.3.5
[2.3.4]: https://github.com/Automattic/jetpack-jitm/compare/v2.3.3...v2.3.4
[2.3.3]: https://github.com/Automattic/jetpack-jitm/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/Automattic/jetpack-jitm/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/Automattic/jetpack-jitm/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.42...v2.3.0
[2.2.42]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.41...v2.2.42
[2.2.41]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.40...v2.2.41
[2.2.40]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.39...v2.2.40
[2.2.39]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.38...v2.2.39
[2.2.38]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.37...v2.2.38
[2.2.37]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.36...v2.2.37
[2.2.36]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.35...v2.2.36
[2.2.35]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.34...v2.2.35
[2.2.34]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.33...v2.2.34
[2.2.33]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.32...v2.2.33
[2.2.32]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.31...v2.2.32
[2.2.31]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.30...v2.2.31
[2.2.30]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.29...v2.2.30
[2.2.29]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.28...v2.2.29
[2.2.28]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.27...v2.2.28
[2.2.27]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.26...v2.2.27
[2.2.26]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.25...v2.2.26
[2.2.25]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.24...v2.2.25
[2.2.24]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.23...v2.2.24
[2.2.23]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.22...v2.2.23
[2.2.22]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.21...v2.2.22
[2.2.21]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.20...v2.2.21
[2.2.20]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.19...v2.2.20
[2.2.19]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.18...v2.2.19
[2.2.18]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.17...v2.2.18
[2.2.17]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.16...v2.2.17
[2.2.16]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.15...v2.2.16
[2.2.15]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.14...v2.2.15
[2.2.14]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.13...v2.2.14
[2.2.13]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.12...v2.2.13
[2.2.12]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.11...v2.2.12
[2.2.11]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.10...v2.2.11
[2.2.10]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.9...v2.2.10
[2.2.9]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.8...v2.2.9
[2.2.8]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.7...v2.2.8
[2.2.7]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.6...v2.2.7
[2.2.6]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.5...v2.2.6
[2.2.5]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.4...v2.2.5
[2.2.4]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.3...v2.2.4
[2.2.3]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.2...v2.2.3
[2.2.2]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/Automattic/jetpack-jitm/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/Automattic/jetpack-jitm/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/Automattic/jetpack-jitm/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.8...v2.1.0
[2.0.8]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.7...v2.0.8
[2.0.7]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.6...v2.0.7
[2.0.6]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.5...v2.0.6
[2.0.5]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.4...v2.0.5
[2.0.4]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.3...v2.0.4
[2.0.3]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/Automattic/jetpack-jitm/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.16.2...v2.0.0
[1.16.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.16.1...v1.16.2
[1.16.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.16.0...v1.16.1
[1.16.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.15.1...v1.16.0
[1.15.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.15.0...v1.15.1
[1.15.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.14.1...v1.15.0
[1.14.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.13.5...v1.14.0
[1.13.5]: https://github.com/Automattic/jetpack-jitm/compare/v1.13.4...v1.13.5
[1.13.4]: https://github.com/Automattic/jetpack-jitm/compare/v1.13.3...v1.13.4
[1.13.3]: https://github.com/Automattic/jetpack-jitm/compare/v1.13.2...v1.13.3
[1.13.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.13.1...v1.13.2
[1.13.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.12.2...v1.13.0
[1.12.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.12.1...v1.12.2
[1.12.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.12.0...v1.12.1
[1.12.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.11.2...v1.12.0
[1.11.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.11.1...v1.11.2
[1.11.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.10.4...v1.11.0
[1.10.4]: https://github.com/Automattic/jetpack-jitm/compare/v1.10.3...v1.10.4
[1.10.3]: https://github.com/Automattic/jetpack-jitm/compare/v1.10.2...v1.10.3
[1.10.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.9.1...v1.10.0
[1.9.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.6.5...v1.7.0
[1.6.5]: https://github.com/Automattic/jetpack-jitm/compare/v1.6.4...v1.6.5
[1.6.4]: https://github.com/Automattic/jetpack-jitm/compare/v1.6.3...v1.6.4
[1.6.3]: https://github.com/Automattic/jetpack-jitm/compare/v1.6.2...v1.6.3
[1.6.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.10...v1.1.0
[1.0.10]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.9...v1.0.10
[1.0.9]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Automattic/jetpack-jitm/compare/v1.0.0...v1.0.1
