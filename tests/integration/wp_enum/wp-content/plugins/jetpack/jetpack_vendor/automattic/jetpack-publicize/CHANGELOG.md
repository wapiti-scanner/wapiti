# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.25.1] - 2023-05-01
### Fixed
- Jetpack Social: Render Social Image Generator panel even when SIG's default is disabled [#30358]

## [0.25.0] - 2023-04-25
### Added
- Added new option for flagging a post as social post [#30179]

### Changed
- Added dynamic pricing to Social admin page [#30105]
- Use attached media for the OpenGraph image [#30162]

## [0.24.2] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

### Fixed
- Reinstated is_social_image_generator_enabled for backwards compatibility [#29952]

## [0.24.1] - 2023-04-04
### Changed
- Updated package dependencies. [#29854]

## [0.24.0] - 2023-03-28
### Changed
- Jetpack Social: Enable Social Image Generator by default when it's available. [#29742]
- Use picked default template for Social Image Generator [#29722]

## [0.23.0] - 2023-03-27
### Added
- Add new endpoint to Social Image Generator to get and update SIG-specific options [#29624]
- Social: Added an endpoint to generate a token for use as the preview of the social image. [#29596]

### Changed
- Moved SIG initilization to the admin_init hooks and updated the check to find out whether SIG is enabled to use the current plans package and added code to refresh plan data on every jetpack heartbeat." [#29529]
- Updated package dependencies. [#29529]
- Use TemplatePicker to save selected template and send it to our token generation endpoint [#29590]

## [0.22.0] - 2023-03-20
### Added
- Added SIG image to the post media array if it's enabled [#29093]

### Changed
- Updated package dependencies. [#29471]

### Fixed
- Prevent metadata updates during autosave. [#29263]

## [0.21.0] - 2023-03-13
### Added
- Add Social Image Generator class to Publicize [#29118]

## [0.20.1] - 2023-03-08
### Changed
- Updated package dependencies. [#29216]

## [0.20.0] - 2023-02-28
### Added
- Add options panel for Social Image Generator to Jetpack Social sidebar. [#28737]
- Add Social Image Generator feature flag to Jetpack Social [#29001]

## [0.19.5] - 2023-02-20
### Changed
- Minor internal updates.

## [0.19.4] - 2023-02-15
### Changed
- Update to React 18. [#28710]

### Fixed
- Configure with standard `@wordpress/browserslist-config` config. [#28910]

## [0.19.3] - 2023-02-08
### Changed
- Minor internal updates.

## [0.19.2] - 2023-01-26
### Changed
- Minor internal updates.

## [0.19.1] - 2023-01-11
### Changed
- Changed attached_media type [#27840]

## [0.19.0] - 2023-01-02
### Added
- Added already shared meta value for post editor api. [#28072]

## [0.18.4] - 2022-12-19
### Changed
- Updated package dependencies. [#27962]

## [0.18.3] - 2022-12-12
### Added
- Social: Added a 'more info' link to the plan details in the editor nudge [#27617]

## [0.18.2] - 2022-12-06
### Changed
- Updated package dependencies. [#27688, #27696]

## [0.18.1] - 2022-11-28
### Changed
- Updated package dependencies. [#27043]

## [0.18.0] - 2022-11-14
### Changed
- Save attached media to post meta [#26930]

## [0.17.3] - 2022-11-08
### Changed
- Updated package dependencies. [#27289]

## [0.17.2] - 2022-11-01
### Changed
- Updated package dependencies. [#27196]

## [0.17.1] - 2022-10-28
### Fixed
- Classic Editor: fix the is_healthy logic that disabled connections. [#27159]
- Include built JavaScript bundles in the package. [#27152]

## [0.17.0] - 2022-10-25
### Added
- Cache connection testing results during an HTTP request. [#26955]
- Social: Add the reshare endpoint for proxying the request to WPCOM [#25993]

### Changed
- Updated package dependencies. [#26705]

### Fixed
- Display error for broken connections in editor [#25803]

## [0.16.2] - 2022-10-11
### Changed
- Updated package dependencies. [#26640]

## [0.16.1] - 2022-10-05
### Changed
- Updated package dependencies. [#26569]

## [0.16.0] - 2022-09-27
### Added
- Add caching to shares info check [#26449]

### Changed
- Move share limits code to the Publicize package [#26294]
- Social: Aligned Jetpack and Social to use the connection-test-results endpoint in the block editor [#26274]
- Updated package dependencies. [#26294]

## [0.15.0] - 2022-09-20
### Added
- Added is-healthy endpoint to post field [#26216]

## [0.14.0] - 2022-09-13
### Added
- Added hooks for Publicize form in Classic Editor [#26039]

## [0.13.2] - 2022-09-08
### Changed
- Updated package dependencies.

### Fixed
- Fixed wrong permissions check for contributors [#26025]

## [0.13.1] - 2022-08-31
### Removed
- Removed errant code change.

## [0.13.0] - 2022-08-31
### Changed
- Updated package dependencies. [#25931]

## [0.12.0] - 2022-08-30
### Changed
- Rebrand Publicize to Jetpack Social [#25787]
- Updated package dependencies. [#25694]

### Fixed
- Post field: Allow for the filter which could make the connections default to disabled. [#24617]

## [0.11.1] - 2022-08-23
### Changed
- Updated package dependencies. [#25628]

## [0.11.0] - 2022-08-09
### Added
- Added scheduled post calculation on plugin activation [#25334]

## [0.10.1] - 2022-08-03
### Changed
- Updated package dependencies. [#25300, #25315]

## [0.10.0] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]
- Use new Jetpack Social endpoint on WPCOM to get Publicize shares info [#25147]

## [0.9.0] - 2022-07-19
### Added
- Fetch share counter on the server side in Jetpack Social. To facilitate this, the call to wpcom has been moved into the Publicize_Base class. [#24836]

## [0.8.1] - 2022-07-12
### Changed
- Updated package dependencies.

## [0.8.0] - 2022-07-06
### Added
- Synced changes made in modules/publice/publicize.php and made sure the composer package for publicize has those changes. [#24943]

## [0.7.1] - 2022-06-29
### Changed
- Update annotations versions.

## [0.7.0] - 2022-06-21
### Added
- Added a proxy end-point to get the shares count for Publicize. [#24786]

### Changed
- Renaming master to trunk. [#24661]

## [0.6.0] - 2022-06-14
### Added
- Made changes to not instantiate the publicize object, if it's already instantiated. [#24695]

### Changed
- Publicize: Allow users to set the image for their social post even when themes don't support featured images. [#23871]
- Updated package dependencies. [#24529]

## [0.5.0] - 2022-05-31
### Added
- Changed logic to initialize publicize classes only if the publicize module is active. [#24451]

### Changed
- Classic Editor: Replaced the initial settings form with the Jetpack redirect link [#24526]

## [0.4.0] - 2022-05-24
### Added
- Added the post field to the Publicize package [#24324]

## [0.3.0] - 2022-05-18
### Added
- Added new jetpack v4 end-point to list publicize connections. [#24293]

### Changed
- Updated package dependencies. [#24153] [#24360]

### Fixed
- Added check for wp_ajax_elementor_ajax to allow publicizing via elementor. [#24387]
- gitignore wordpress directory within the publicize package [#24339]

## [0.2.1] - 2022-05-10
### Fixed
- Publicize: Correct bad namespaces

## [0.2.0] - 2022-05-04
### Added
- Added redirect links for Jetpack cloud. [#24205]

### Changed
- Updated package dependencies. [#24095]

### Deprecated
- Moved the options class into Connection. [#24095]

## [0.1.1] - 2022-05-19
### Fixed
- Added check for wp_ajax_elementor_ajax to allow publicizing via elementor.
- Publicize: Correct bad namespaces

## 0.1.0 - 2022-04-26
### Added
- Added an empty shell package
- Added Publicize module files to Composer package
- Set composer package type to "jetpack-library" so i18n will work.
- Use the publicize package in the Jetpack plugin.

### Changed
- Applied legacy Publicize filters to flag setting for Publicize
- Fix Composer dependencies
- Microperformance: Use === null instead of is_null
- PHPCS: Fix `WordPress.Security.ValidatedSanitizedInput`
- Publicize: Do not display legacy UI for block editor pages
- Sync'd changes with the equivalent files in the Publicize module
- Updated package dependencies.
- Update package.json metadata.

[0.25.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.25.0...v0.25.1
[0.25.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.24.2...v0.25.0
[0.24.2]: https://github.com/Automattic/jetpack-publicize/compare/v0.24.1...v0.24.2
[0.24.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.24.0...v0.24.1
[0.24.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.20.1...v0.21.0
[0.20.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.20.0...v0.20.1
[0.20.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.19.5...v0.20.0
[0.19.5]: https://github.com/Automattic/jetpack-publicize/compare/v0.19.4...v0.19.5
[0.19.4]: https://github.com/Automattic/jetpack-publicize/compare/v0.19.3...v0.19.4
[0.19.3]: https://github.com/Automattic/jetpack-publicize/compare/v0.19.2...v0.19.3
[0.19.2]: https://github.com/Automattic/jetpack-publicize/compare/v0.19.1...v0.19.2
[0.19.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.18.4...v0.19.0
[0.18.4]: https://github.com/Automattic/jetpack-publicize/compare/v0.18.3...v0.18.4
[0.18.3]: https://github.com/Automattic/jetpack-publicize/compare/v0.18.2...v0.18.3
[0.18.2]: https://github.com/Automattic/jetpack-publicize/compare/v0.18.1...v0.18.2
[0.18.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.17.3...v0.18.0
[0.17.3]: https://github.com/Automattic/jetpack-publicize/compare/v0.17.2...v0.17.3
[0.17.2]: https://github.com/Automattic/jetpack-publicize/compare/v0.17.1...v0.17.2
[0.17.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.16.2...v0.17.0
[0.16.2]: https://github.com/Automattic/jetpack-publicize/compare/v0.16.1...v0.16.2
[0.16.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.16.0...v0.16.1
[0.16.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.13.2...v0.14.0
[0.13.2]: https://github.com/Automattic/jetpack-publicize/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Automattic/jetpack-publicize/compare/v0.1.0...v0.2.0
[0.1.1]: https://github.com/Automattic/jetpack-publicize/compare/v0.1.0...v0.1.1
