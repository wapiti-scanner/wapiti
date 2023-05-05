# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.36.2] - 2023-05-01
### Changed
- Internal updates.

## [0.36.1] - 2023-04-25

- Minor internal updates.

## [0.36.0] - 2023-04-17
### Added
- Search: Restore Tracks to Instant Search [#29979]

### Changed
- Updated package dependencies. [#30019]

## [0.35.0] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]
- Implemented a "tabbed" variation for static filters. This adds tabs on top of the results for each filter group. [#29811]

## [0.34.4] - 2023-04-04
### Changed
- Updated package dependencies. [#29854, #29857]

## [0.34.3] - 2023-04-03
### Changed
- Internal updates.

## [0.34.2] - 2023-03-28
### Changed
- Minor internal updates.

## [0.34.1] - 2023-03-27
### Added
- (Backup, Boost, Search, Social) Add links on upgrade pages to activate a license key, if you already have one. [#29443]

### Changed
- Updated package dependencies. [#29632]

## [0.34.0] - 2023-03-20
### Changed
- Updated package dependencies. [#29471]

### Removed
- Remove Tracks from Instant Search [#29490]

## [0.33.3] - 2023-03-13
### Fixed
- Search Dashboard: fix wrong return URL when site already has a valid subscription [#29409]

## [0.33.2] - 2023-03-08
### Changed
- Updated package dependencies. [#29216]

### Fixed
- Fix bad check against isMultiSite resulting in extended search format not showing expected additional post details. [#29179]

## [0.33.1] - 2023-02-28
### Added
- Search: Add JITM container [#29106]

### Changed
- Updated package dependencies.

### Fixed
- Fix CSS for products in search results [#29110]

## [0.33.0] - 2023-02-20
### Added
- Adds a "show post date" selector to Search customberg, allows non-multisite sites to show the post date in the "expanded" search result format. [#28918]

### Fixed
- Fixed unit tests without internet [#28985]
- Separated authors by comments if there are multiple authors in a search result [#28975]

## [0.32.0] - 2023-02-15
### Added
- Search: Adds assigned post categories as classnames to search results [#28816]

### Changed
- Update to React 18. [#28710]

## [0.31.7] - 2023-02-08
### Changed
- Updated package dependencies. [#28682]

## [0.31.6] - 2023-01-30
### Changed
- Increased Jetpack Search filters caching from one hour to four hours [#28632]

## [0.31.5] - 2023-01-26
### Changed
- Minor internal updates.

## [0.31.4] - 2023-01-23
### Changed
- Start using utilities from Status package to detect whether a site is private or "coming-soon" (unlaunched). [#28328]

### Fixed
- Clean up JavaScript eslint issues. [#28441]

## [0.31.3] - 2023-01-11
### Changed
- Updated package dependencies.

## [0.31.2] - 2022-12-19
### Changed
- Updated package dependencies. [#27887, #27916, #27962]

### Fixed
- Declare field `REST_Controller->plan`. [#27949]
- Improve PHP 8.2 compatibility. [#27968]

## [0.31.1] - 2022-12-06
### Changed
- Updated package dependencies. [#27340, #27688, #27696, #27697]

## [0.31.0] - 2022-11-28
### Added
- Add an optional global flag that prevents instant search from modifying the url as the search query is being written or modified. [#27264]
- Add prompt for Jetpack Search Free plan upgrade for users who exceed limits. [#27462]
- Search: Add checkmark icon for resolved topics [#27586]

### Changed
- Suggest free Jetpack Search plan instead of the paid one to classic search users [#27372]
- Updated package dependencies. [#26069]

## [0.30.2] - 2022-11-10
### Changed
- Updated package dependencies. [#27319]

### Fixed
- Jetpack Search: Fixed link to language support documentation [#27287]

## [0.30.1] - 2022-11-07
### Changed
- Updated package dependencies. [#27278]

## [0.30.0] - 2022-11-01
### Added
- Search: add blog ID filtering and `blogIdFilteringLabels` option [#27120]

### Changed
- Updated package dependencies. [#27089]

## [0.29.2] - 2022-10-26
### Fixed
- Search: Fix typo in CTA [#27044]
- Search: hide meters etc for Classic Search [#27073]

## [0.29.1] - 2022-10-25
### Added
- Search: add purchase tracking [#26981]

### Changed
- Search: now support 38 languages [#27025]
- Tweak colophon link to Search upgrade page [#26952]
- Updated package dependencies. [#26705]

### Fixed
- Hide Jetpack logo toggle, enforce display for free plans [#26951]
- Search: Hide post-purchase tooltips for free plan activation [#26953]

## [0.29.0] - 2022-10-19
### Added
- Search: enable new pricing if pricing_version is set to 202208 from API [#26900]

### Changed
- Updated package dependencies. [#26808]
- Use API values for paid allowance limits shown in the new pricing table [#26895]

## [0.28.0] - 2022-10-17
### Changed
- Check free plan by product_slug and disable Module Control only on free plan. [#26849]
- Fetch checkoutProductUrl for upgrade flow redirection. [#26848]
- Introduce GET param just_upgraded and localStorage upgrade_tooltip_finished to determine the tooltips showing. [#26828]
- Refactor upgrade tooltips. [#26851]
- Search: always add Search Dashboard page even when submenu is hidden [#26807]
- Search Dashboard: Add missing CTAs and associated logic. [#26852]
- Search Dashboard: Add siteTitle to plugin/package data. [#26816]
- Search Dashboard: Better handling of "Unlimited" requests. [#26813]
- Search Dashboard: Disable adaptive colors for Unlimited requests state. [#26850]
- Search Dashboard: Fix responsive layouts for usage meters. [#26815]
- Search Dashboard: Remove code duplication for support link. [#26811]
- Search Dashboard: Update Plan Usage section to remove info icons. [#26812]
- Updated package dependencies. [#26851]
- Use adaptive coloring for donut meters in search dashboard [#26847]

## [0.27.0] - 2022-10-13
### Added
- Add connection error notice to the Search plugin. [#26778]
- Introduce shadowed IconTooltips to tooltips for highlighting upgraded usage limits. [#26790]

### Changed
- Add upgrade button link with applying upgrade actions. [#26737]
- Search Dashboard: Update Plan Usage section to more closely match design. [#26783]
- Updated package dependencies. [#26790]

### Fixed
- Search: wpcom sites should not be considered as connected [#26835]

## [0.26.0] - 2022-10-11
### Added
- Search Dashboard: Add support for conditional CUTs. [#26656]

### Changed
- Apply ContextualUpgradeTrigger with checkout CTA [#26633]
- Apply tier and latest month usage to plan summary [#26695]
- Apply upgrade trigger displaying conditions and messages from API data [#26712]
- Stop controls when usage over plan limit months. [#26732]
- Updated package dependencies. [#26640]

### Fixed
- Fixed search dashboard for simple sites. [#26713]
- Search Dashboard: Add support link for plan limits. [#26694]
- Search Dashboard: Refactoring of new UI components. [#26723]
- Search Dashboard: Rename variables to avoid jargon. [#26691]

## [0.25.0] - 2022-10-05
### Added
- Added string translations used for the new pricing table [#26595]
- Components: Added UsageMeter along with DonutMeterContainer JS component. [#26344]
- Search: add post type breakdown endpoint [#26463]

### Changed
- Apply JetpackSearchLogo and replace footer link to upsell page [#26481]
- Search: add connection support for new pricing page [#26573]
- Search Dashboard: Added first run and usage section components. [#26639]
- Updated package dependencies. [#26457]
- Use library method for number formatting. [#26636]

### Fixed
- Search: fix redirection after purchase [#26598]

## [0.24.0] - 2022-10-03
### Changed
- Fix styles of Control components on page side to avoid deprecating component styles affecting. [#26567]

## [0.23.0] - 2022-09-27
### Added
- Added stories for the NoticeBox component [#26367]
- Search: added free_tier and new_pricing_202208 to gate new pricing features [#26338]

### Changed
- Introduce PricingTable to update Upsell page [#26408]
- Move JetpackColophon to bottom of SearchResults [#26320]
- Updated mentions of "Search" with "Jetpack Search" as part of rebranding project [#26410]
- Updated package dependencies.

### Fixed
- Fix error message styling in Instant Search overlay. [#26339]

## [0.22.2] - 2022-09-20
### Changed
- Updated package dependencies.

### Fixed
- Fixes the issue where search results are not loaded in customizer [#26212]

## [0.22.1] - 2022-09-13
### Changed
- Updated package dependencies. [#26176]

## [0.22.0] - 2022-09-08
### Added
- Search: added support to search through multiple sites [#26046]

### Changed
- Updated package dependencies.

### Fixed
- Instant Search: Update CSS styles to removes uses of "!important" where possible. [#25825]
- Search: Allow non-owner admins to see search dashboard [#26100]
- Search: fixed Automattic link in footer when Jetpack plugin does not exist [#26045]

## [0.21.1] - 2022-08-30
### Added
- Instant Search: add focus border to search input field [#25304]

### Changed
- Updated package dependencies. [#25694]

### Fixed
- Keep widget preview with settings [#25778]

## [0.21.0] - 2022-08-25
### Changed
- Search: revert "Search should not require user connection" [#25802]
- Updated package dependencies. [#25814]

## [0.20.0] - 2022-08-23
### Added
- Add author filtering support [#25409]

### Changed
- Updated package dependencies. [#25338, #25339, #25377, #25628, #25762, #25769]

### Fixed
- Instant Search: Add focus styles for easier keyboard navigation. (a11y) [#25671]
- Instant Search: Remove redundant links from search results. (a11y) [#25699]

## [0.19.0] - 2022-08-16
### Added
- Instant Search: always use submit overlay trigger if user prefers reduced motion. [#25413]
- Instant Search: only show animation to users who have not chosen reduced motion. [#25630]
- Instant Search: user friendly error messaging. [#25433]

### Fixed
- Instant Search: fix button styling in Twenty Twenty One theme. [#25631]
- Instant Search: fix the display order on mobile to match the tab order. [#25415]
- Instant Search: use classname rather than ID for styling sort select. [#25632]

## [0.18.0] - 2022-08-09
### Added
- Search: added proper error messages for search module control [#24476]

### Changed
- Instant Search: Updates dark mode active link color for increased contrast [#25343]
- Search: changed to only require site level connection [#24477]
- Updated package dependencies. [#24477, #25265]

### Removed
- Search: remove 'results' overlay trigger [#25393]

### Fixed
- Dashboard: updated Instant Search description to match changes in default overlay trigger [#25303]
- Instant Search: Constrain tab loop to overlay when visible. [#25288]
- Instant Search: Make "Clear filters" button accessible. [#25342]

## [0.17.1] - 2022-08-03
### Added
- Instant Search: Adds descriptions to post type icons for accessibility purposes [#25323]
- Record Meter: add info link to docs [#25002]

### Changed
- Updated package dependencies. [#25300, #25315]

### Fixed
- Instant Search: Improve accessibility of seach options controls.
- Search: ensure overlay trigger is consistent for new installs [#25093]

## [0.17.0] - 2022-07-29
### Added
- Record Meter: make feature available to all users
- Search: re-add 'Media' to 'Excluded Post Types'

## [0.16.2] - 2022-07-26
### Added
- Dashboard: added support WPCOM simple sites [#25094]

### Changed
- Instant search: updates overlay focus elements for design consistency [#25260]
- Updated package dependencies. [#25144]
- Updated package dependencies. [#25147]
- Updated package dependencies. [#25158]

### Fixed
- Instant Search: Fix keyboard handling of sort options. [#25163]
- Instant Search: prevent hidden submit button appearing on focus [#25136]
- Search Dashboard: Fixed layout issues when Hello Dolly plugin is active. [#25139]

## [0.16.1] - 2022-07-19
### Changed
- Updated package dependencies. [#25086]

### Fixed
- Customberg: re-add collapsing wp-admin sidebar to prevent menu overlap issue [#25060]
- Fixed the currency code missing issue for the upsell page [#25068]

## [0.16.0] - 2022-07-12
### Added
- Hide unsupported taxonomies from widget settings [#24823]

### Changed
- Updated package dependencies. [#25055]

### Fixed
- Fix irrelevant widgets in overlay sidebar [#24824]
- Hide 'Media' from 'Excluded Post Types' because we don't index them [#24822]
- Record Meter: rely less on last_indexed_date from API [#24967]
- Use consistent number formatting in Record Meter [#25003]

## [0.15.4] - 2022-07-06
### Added
- Record Meter: adds labels to custom post type breakdown [#24876]

### Changed
- Updated package dependencies. [#24923]

### Removed
- Record Meter: Remove dismissable functionality and design from notice boxes [#24922]

### Fixed
- Reset letter spacing for header tags [#24954]
- Restores support for multiple post types in the Jetpack Search Widget. [#24868]

## [0.15.3] - 2022-06-28
### Changed
- Record meter: format the numbers used in notice. [#24810]
- Record Meter: updated notice box content when site is not indexed [#24785]
- Search: use centralized search pricing API [#24795]
- Updated package dependencies. [#24826]

### Fixed
- Added My Jetpack package as dependency [#24826]

## [0.15.2] - 2022-06-21
### Changed
- Record Meter: Separated component styles [#24732]
- Renaming master to trunk. [#24661]

## [0.15.1] - 2022-06-14
### Changed
- Search record meter: pass sorted records to RecordMeterBar component [#24731]
- Updated package dependencies. [#24529]

## [0.15.0] - 2022-06-08
### Changed
- Record Meter: switches from using chartJS to the Jetpack RecordMeterBar component [#24322]
- Reorder JS imports for `import/order` eslint rule. [#24601]
- Search record meter: changed the notice box to include a header text [#24346]
- Search widget: use 'Search (Jetpack)' as wdiget name and remove `jetpack_widget_name` [#24577]
- Updated package dependencies. [#24510]

### Removed
- Search: don't open modal if only sort parameter is set [#24576]
- Search: Removed unused chart.js library [#24658]

### Fixed
- Search: avoid query on component mount when the overlay might not be visible [#24609]
- Search: fix gridicon color in dark mode on Customberg [#24668]

## [0.14.2] - 2022-05-30
### Changed
- Updated package dependencies
- Updated package dependencies.
- Use the Checkout workflow to establish the connection and make the purchase

### Fixed
- Avoid filter from being added multiple times

## [0.14.1] - 2022-05-24
### Added
- Allow plugins to filter the list of available modules. Only activate and consider active modules that are available [#24454]

### Changed
- Search: Use Modules methods for activating and deactivating the Search module. [#24385]
- Updated package dependencies. [#24449]

## [0.14.0] - 2022-05-19
### Removed
- Search: Disable auto-collapsing the wp-admin sidebar within Customberg [#24399]

## [0.13.4] - 2022-05-18
### Changed
- Adjust translatable string [#24357]
- Record Meter: switch noticebox persistence storage from localStorage to sessionStorage [#24348]
- Record Meter design updates [#24225]
- Search package: search dashboard refactoring [#24266]
- Updated package dependencies. [#23795] [#24153] [#24306] [#24372]

## [0.13.3] - 2022-05-10
### Added
- Add missing JS dep on `core-js`. [#24288]

### Changed
- Search: refactored Settings to expose the settings array for sync [#24167]
- Updated package dependencies. [#24189]
- Updated package dependencies. [#24204]
- Updated package dependencies. [#24302]
- Updated package dependencies [#24276]
- Updated package dependencies [#24296]
- Updated package dependencies [#24301]

### Fixed
- Search: Fix left padding for upsell page [#24285]
- Search: handle tiers without a record limit in Record Meter [#24264]

## [0.13.2] - 2022-05-04
### Added
- Add missing JavaScript dependencies. [#24096]

### Changed
- Remove use of `pnpx` in preparation for pnpm 7.0. [#24210]
- Updated package dependencies. [#24095] [#24230] [#24198] [#24228]

### Deprecated
- Moved the options class into Connection. [#24095]

### Fixed
- Adapt Record Meter to change in API response format [#24107]
- Search: Bundle vendor assets within the main chunk [#24068]
- Search: Fix search for private WoA sites [#24099]
- Search: reset border-radius for search buttons [#24100]

## [0.13.1] - 2022-04-26
### Added
- Search: added upsell page

### Changed
- Updated package dependencies.
- Update package.json metadata.

## [0.13.0] - 2022-04-19
### Added
- Search: add class to retrieve search product information
- Search: Add count estimation function
- Search: added API support for search product tier pricing

### Changed
- PHPCS: Fix `WordPress.Security.ValidatedSanitizedInput`
- Record meter: updates noticeboxes to be dismissable & styled
- Search Record Meter updates formatting
- Use new shared Gridicons component and shared Modules library

## [0.12.3] - 2022-04-12
### Added
- Added deprecated methods as a safety.

### Changed
- Updated package dependencies.

### Fixed
- Search: auto config no longer overrides option if it exists.

## [0.12.2] - 2022-04-06
### Added
- Adds API data to record meter chart.

### Changed
- Janitorial: Refactor classes into shared package.
- Updated package dependencies.

### Removed
- Removed tracking dependency.

### Fixed
- Search: allow Search submenu to be added only once

## [0.12.1] - 2022-03-31
### Fixed
- Search: fixed search submenu is shown because compatibility file is loaded too late.

## [0.12.0] - 2022-03-29
### Added
- Add selector for retrieving last indexed date
- Adds notice box component to record meter
- Search: Migrated tests from Jetpack plugin

### Changed
- Microperformance: Use === null instead of is_null
- Search: connection states
- Updated package dependencies

### Fixed
- Fixed lints found after fixing ESLint config
- Search: address feeback for #23477
- Search: move Jetpack plugin compatibility to the package

## [0.11.3] - 2022-03-24
### Added
- Search: adds a record count above the record meter chart.

### Fixed
- Deactivation: Do not attempt to redirect on a behind-the-scene deactivation.

## [0.11.2] - 2022-03-23
### Added
- adds basic structure for record meter with dummy data

### Changed
- Centralized all intializing logic
- Search dashboard: changed condition to always show dashboard submenu
- Updated package dependencies
- Use Migrated GlotPress locale classes from compat pkg.

### Fixed
- Search: fixed cli and package version reporting broken in #23435

## [0.11.1] - 2022-03-15
### Changed
- Fixed minor product defects
- Search: moved globals to a class for sake of autoloading correctly
- Search package: Updated Gridicon dependancy to use local version
- Updated package dependencies.

## [0.11.0] - 2022-03-08
### Changed
- Components: update attributes used within the Button component to match recent deprecations and changes.
- Move customizer integration into search package
- search: move record meter location on dashboard

### Fixed
- Ensure that WP CLI is present before extending the class.
- Ensure the Customizer classes are loaded.

## [0.10.0] - 2022-03-02
### Added
- Search: add chart.js package to dependencies
- Search: fetch search stats endpoint in wp-admin dashboard

### Changed
- Search: Renamed Customberg class file name
- Updated package dependencies.

### Fixed
- Fix various notices shown for Customberg
- Search package: i18n support for auto added search block label and button

## [0.9.1] - 2022-02-25
### Fixed
- Search: Fixed a regression that prevented modal from being spawned by link clicks

## [0.9.0] - 2022-02-22
### Added
- Bump package versions.
- Search: add stats endpoint to REST controller

### Changed
- Search package: refactor `auto_config_search` and run it from activation API

### Fixed
- Search package: fix auto config doesn't add search input for block themes

## [0.8.0] - 2022-02-16
### Added
- Add babel/runtime to dev dependencies
- Add tier maximum records for Record Meter
- Clicking outside overlay now closes overlay

### Changed
- Change `instance` function for improved compatibility
- Updated package dependencies.

### Fixed
- Form: avoid React warning.
- Improve display of colorpicker in Customberg
- Fixed undefined index features
- Should not exclude widget js in package distribution

## [0.7.0] - 2022-02-09
### Added
- Search Dashboard: add scaffolding for new record meter
- Search package: added auto config CLI

### Changed
- Search: move search widgets to package
- Updated package dependencies

## [0.6.0] - 2022-02-02
### Added
- Add `@use "sass:math"` in base styles scss for upcoming `@wordpress/block-editor` 8.1.0 requirement.
- Search package: added package version number and others

### Changed
- Build: remove unneeded files from production build.
- Instant Search: add image alt text from API
- Updated package dependencies.

## [0.5.4] - 2022-01-31
### Fixed
- Search: Fetch plan info as blog, not as user, to allow nonconnected admins to use dashboard

## [0.5.3] - 2022-01-27
### Fixed
- Search package: fixed compatibility issue with plan activation

## [0.5.2] - 2022-01-25
### Added
- Added a watch command for building assets
- Search E2E: added class names for some form components for easier E2E tests

### Changed
- Search: Improve accessibility via headings hierarchy and aria roles
- Updated package dependencies.

### Fixed
- Search widget: changed fetching search result to just before rendering jp search widget

## [0.5.1] - 2022-01-18
### Changed
- General: update required node version to v16.13.2

## [0.5.0] - 2022-01-11
### Added
- Search: Migrated Classic and Instant Search code from Jetpack plugin.
- Search API: activation and deactivation API.

### Changed
- Search: moved search dashboard to the package.
- Updated package dependencies.

## [0.4.0] - 2022-01-04
### Changed
- Do not escape widget title value
- Switch to pcov for code coverage.
- Updated package dependencies.
- Updated package textdomain from `jetpack` to `jetpack-search-pkg`.

### Fixed
- Add missing textdomains in JS code.

## [0.3.0] - 2021-12-14
### Changed
- Search package: add new methods and update timing for `Plan` class.
- Search package: refactored Module_Control class.

## [0.2.1] - 2021-12-07
### Changed
- Updated package dependencies.

## [0.2.0] - 2021-11-30
### Added
- Added essential scaffolding for package.
- Migrate additional helper classes to package
- Search: added new state store for search dashboard
- Search package: duplicated search dashboard dependencies to the package

### Changed
- Search: migrate/create necessary APIs for the frontend
- Search: removed other dependencies from copied code

## 0.1.0 - 2021-11-09
### Added
- Add a new Search package with Helper and Options classes.
- Search: Migrate helper classes from Jetpack plugin

### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Updated package dependencies.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

[0.36.2]: https://github.com/Automattic/jetpack-search/compare/v0.36.1...v0.36.2
[0.36.1]: https://github.com/Automattic/jetpack-search/compare/v0.36.0...v0.36.1
[0.36.0]: https://github.com/Automattic/jetpack-search/compare/v0.35.0...v0.36.0
[0.35.0]: https://github.com/Automattic/jetpack-search/compare/v0.34.4...v0.35.0
[0.34.4]: https://github.com/Automattic/jetpack-search/compare/v0.34.3...v0.34.4
[0.34.3]: https://github.com/Automattic/jetpack-search/compare/v0.34.2...v0.34.3
[0.34.2]: https://github.com/Automattic/jetpack-search/compare/v0.34.1...v0.34.2
[0.34.1]: https://github.com/Automattic/jetpack-search/compare/v0.34.0...v0.34.1
[0.34.0]: https://github.com/Automattic/jetpack-search/compare/v0.33.3...v0.34.0
[0.33.3]: https://github.com/Automattic/jetpack-search/compare/v0.33.2...v0.33.3
[0.33.2]: https://github.com/Automattic/jetpack-search/compare/v0.33.1...v0.33.2
[0.33.1]: https://github.com/Automattic/jetpack-search/compare/v0.33.0...v0.33.1
[0.33.0]: https://github.com/Automattic/jetpack-search/compare/v0.32.0...v0.33.0
[0.32.0]: https://github.com/Automattic/jetpack-search/compare/v0.31.7...v0.32.0
[0.31.7]: https://github.com/Automattic/jetpack-search/compare/v0.31.6...v0.31.7
[0.31.6]: https://github.com/Automattic/jetpack-search/compare/v0.31.5...v0.31.6
[0.31.5]: https://github.com/Automattic/jetpack-search/compare/v0.31.4...v0.31.5
[0.31.4]: https://github.com/Automattic/jetpack-search/compare/v0.31.3...v0.31.4
[0.31.3]: https://github.com/Automattic/jetpack-search/compare/v0.31.2...v0.31.3
[0.31.2]: https://github.com/Automattic/jetpack-search/compare/v0.31.1...v0.31.2
[0.31.1]: https://github.com/Automattic/jetpack-search/compare/v0.31.0...v0.31.1
[0.31.0]: https://github.com/Automattic/jetpack-search/compare/v0.30.2...v0.31.0
[0.30.2]: https://github.com/Automattic/jetpack-search/compare/v0.30.1...v0.30.2
[0.30.1]: https://github.com/Automattic/jetpack-search/compare/v0.30.0...v0.30.1
[0.30.0]: https://github.com/Automattic/jetpack-search/compare/v0.29.2...v0.30.0
[0.29.2]: https://github.com/Automattic/jetpack-search/compare/v0.29.1...v0.29.2
[0.29.1]: https://github.com/Automattic/jetpack-search/compare/v0.29.0...v0.29.1
[0.29.0]: https://github.com/Automattic/jetpack-search/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/Automattic/jetpack-search/compare/v0.27.0...v0.28.0
[0.27.0]: https://github.com/Automattic/jetpack-search/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/Automattic/jetpack-search/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/Automattic/jetpack-search/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/Automattic/jetpack-search/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/Automattic/jetpack-search/compare/v0.22.2...v0.23.0
[0.22.2]: https://github.com/Automattic/jetpack-search/compare/v0.22.1...v0.22.2
[0.22.1]: https://github.com/Automattic/jetpack-search/compare/v0.22.0...v0.22.1
[0.22.0]: https://github.com/Automattic/jetpack-search/compare/v0.21.1...v0.22.0
[0.21.1]: https://github.com/Automattic/jetpack-search/compare/v0.21.0...v0.21.1
[0.21.0]: https://github.com/Automattic/jetpack-search/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/Automattic/jetpack-search/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/Automattic/jetpack-search/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/Automattic/jetpack-search/compare/v0.17.1...v0.18.0
[0.17.1]: https://github.com/Automattic/jetpack-search/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/Automattic/jetpack-search/compare/v0.16.2...v0.17.0
[0.16.2]: https://github.com/Automattic/jetpack-search/compare/v0.16.1...v0.16.2
[0.16.1]: https://github.com/Automattic/jetpack-search/compare/v0.16.0...v0.16.1
[0.16.0]: https://github.com/Automattic/jetpack-search/compare/v0.15.4...v0.16.0
[0.15.4]: https://github.com/Automattic/jetpack-search/compare/v0.15.3...v0.15.4
[0.15.3]: https://github.com/Automattic/jetpack-search/compare/v0.15.2...v0.15.3
[0.15.2]: https://github.com/Automattic/jetpack-search/compare/v0.15.1...v0.15.2
[0.15.1]: https://github.com/Automattic/jetpack-search/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/Automattic/jetpack-search/compare/v0.14.2...v0.15.0
[0.14.2]: https://github.com/Automattic/jetpack-search/compare/v0.14.1...v0.14.2
[0.14.1]: https://github.com/Automattic/jetpack-search/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/Automattic/jetpack-search/compare/v0.13.4...v0.14.0
[0.13.4]: https://github.com/Automattic/jetpack-search/compare/v0.13.3...v0.13.4
[0.13.3]: https://github.com/Automattic/jetpack-search/compare/v0.13.2...v0.13.3
[0.13.2]: https://github.com/Automattic/jetpack-search/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/Automattic/jetpack-search/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/Automattic/jetpack-search/compare/v0.12.3...v0.13.0
[0.12.3]: https://github.com/Automattic/jetpack-search/compare/v0.12.2...v0.12.3
[0.12.2]: https://github.com/Automattic/jetpack-search/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/Automattic/jetpack-search/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/Automattic/jetpack-search/compare/v0.11.3...v0.12.0
[0.11.3]: https://github.com/Automattic/jetpack-search/compare/v0.11.2...v0.11.3
[0.11.2]: https://github.com/Automattic/jetpack-search/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/Automattic/jetpack-search/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/Automattic/jetpack-search/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/Automattic/jetpack-search/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/Automattic/jetpack-search/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Automattic/jetpack-search/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/Automattic/jetpack-search/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Automattic/jetpack-search/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Automattic/jetpack-search/compare/v0.5.4...v0.6.0
[0.5.4]: https://github.com/Automattic/jetpack-search/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/Automattic/jetpack-search/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/Automattic/jetpack-search/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Automattic/jetpack-search/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Automattic/jetpack-search/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Automattic/jetpack-search/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Automattic/jetpack-search/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/Automattic/jetpack-search/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Automattic/jetpack-search/compare/v0.1.0...v0.2.0
