# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.47.8] - 2023-05-01
### Changed
- Internal updates.

## [1.47.7] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.47.6] - 2023-04-04
### Changed
- Sync: Lowered priority to sync so that the hook is run at the end. [#29804]

## [1.47.5] - 2023-04-03
### Changed
- Minor internal updates.

## [1.47.4] - 2023-03-28
### Changed
- Move brute force protection into WAF package. [#28401]

## [1.47.3] - 2023-03-20
### Changed
- Updated package dependencies. [#29480]

## [1.47.2] - 2023-02-20
### Changed
- Minor internal updates.

## [1.47.1] - 2023-01-23
### Added
- Close PHP Session if it's active when running a Dedicated Sync request. [#28515]

### Fixed
- Jetpack Sync: prevent syncing user update when corresponding flags are not set. [#28385]

## [1.47.0] - 2023-01-18
### Removed
- Removed the deprecated option jetpack_blogging_prompts_enabled from defaults [#28387]

## [1.46.1] - 2023-01-11
### Changed
- Updated package dependencies.

## [1.46.0] - 2022-12-27
### Added
- Added woocommerce_cod_settings to the options whitelist. [#27988]

## [1.45.0] - 2022-12-19
### Added
- Adding new boolean site option of 'wpcom-subscription-emails-use-excerpt'. [#27908]
- Sync Launchpad-related options: `launchpad_screen` and `launchpad_checklist_tasks_statuses`. [#27843]

### Changed
- Option: Update featured_image_email_enabled option name to wpcom_featured_image_in_email. [#27955]

### Fixed
- Improve PHP 8.2 compatibility. [#27968]

## [1.44.2] - 2022-12-06
### Changed
- Updated package dependencies.

## [1.44.1] - 2022-12-02
### Changed
- Updated package dependencies. [#27688]

## [1.44.0] - 2022-11-30
### Added
- Added full response logging for failed Sync data requests. [#27644]

### Fixed
- Make sure Dedicated Sync can revert back to Default Sync if it stops sending events for one reason or another. [#27632]

## [1.43.2] - 2022-11-28
### Changed
- Sync: Limit next_sync_time lock to be at most 1 hour in the future [#27606]

## [1.43.1] - 2022-11-22
### Changed
- Updated package dependencies. [#27043]

## [1.43.0] - 2022-11-17
### Added
- Added new sync option for launch-status [#27434]
- Jetpack Sync: Add new endpoint for resetting Sync locks. [#27446]

## [1.42.0] - 2022-11-14
### Changed
- Save attached media to post meta [#26930]

## [1.41.0] - 2022-11-07
### Changed
- Jetpack Sync: add Updates module in required Sync modules. [#27182]
- Updated package dependencies. [#27278]

## [1.40.3] - 2022-11-01
### Added
- Adds wpcom_gifting_subscription option for syncing [#27116]

## [1.40.2] - 2022-10-27
### Fixed
- Check $action_links is still array after plugin_action_links filter has been applied. [#27076]

## [1.40.1] - 2022-10-25
### Added
- Added featured_image_email_enabled option for syncing [#27009]

### Changed
- Search Sync Settings :: Add Marketplace product extra fields meta to allow list [#26927]
- Updated package dependencies. [#26705]

## [1.40.0] - 2022-10-17
### Added
- Adding the `sl-insta-media` post type to the Sync blacklist as the post type data isn't relevant to Sync and takes up non-trivial resources. [#26826]

## [1.39.0] - 2022-10-11
### Added
- Added some taxonomies to be indexed by Search. [#26683]

## [1.38.4] - 2022-09-20
### Added
- Gutenberg Support: add additional theme_supports items to our synced allowlist. [#26239]

### Changed
- Default Theme Support: Add support for new feature added in WP 6.1 [#26236]
- Theme Supports: updated allowed values list to align with a Core change r54159-core [#26220]

## [1.38.3] - 2022-09-08
### Changed
- Updated package dependencies.

## [1.38.2] - 2022-08-29
### Changed
- Updated package dependencies.

## [1.38.1] - 2022-08-25
### Changed
- Search Sync Settings :: Add Marketplace related meta fields and taxonomies to allow list [#25376]

## [1.38.0] - 2022-08-23
### Added
- Search: add product-brand to taxonomy sync list to support WooCommerce Brands plugin. [#25665]

### Changed
- Updated package dependencies. [#25628]

## [1.37.1] - 2022-08-03
### Changed
- Updated package dependencies. [#25300, #25315]

## [1.37.0] - 2022-07-26
### Changed
- Jetpack Sync: Add Sync lock related info in Sync debug details. [#25140]
- Updated package dependencies. [#25158]

### Fixed
- Dedicated Sync: Enable sending of callables outside of admin context, since Dedicated Sync requests always work outside of admin scope. [#25143]

## [1.36.1] - 2022-07-06
### Added
- Add new WordPress core `block-templates` theme feature to `Defaults::$default_theme_support_whitelist` [#24960]

## [1.36.0] - 2022-06-28
### Added
- Posts: added a Sync call to make sure post content is up to date before publishing. [#24827]

### Changed
- Minimum Sync Config: Update required modules and options [#24831]

### Fixed
- Sync Table Checksums:  Table checksum should be enabled depending on corresponding Sync modulee [#24772]

## [1.35.2] - 2022-06-21
### Changed
- Renaming master to trunk. [#24661]

## [1.35.1] - 2022-06-14
### Added
- Add a request lock to prevent multiple requests being spawned at once [#24734]

### Changed
- Updated package dependencies. [#24529]

## [1.35.0] - 2022-05-30
### Changed
- Sync: Add '_jetpack_blogging_prompt_key' to default post meta whitelist

## [1.34.0] - 2022-05-24
### Changed
- Dedicated Sync - Introduce custom endpoint for spawning Sync requests [#24468]
- Sync: Add 'active_modules' to default whitelisted callables. [#24453]

## [1.33.1] - 2022-05-19
### Removed
- Removed dedicated sync custom endpoints pending error investigation [#24419]

## [1.33.0] - 2022-05-18
### Changed
- Dedicated Sync: Introduce custom endpoint for spawning Sync requests [#24344]

## [1.32.0] - 2022-05-10
### Added
- Search: add search options to option whitelist [#24167]

## [1.31.1] - 2022-05-04
### Changed
- Updated package dependencies. [#24095]
- WordPress 6.1 Compatibilty [#24083]

### Deprecated
- Moved the options class into Connection. [#24095]

## [1.31.0] - 2022-04-26
### Added
- Adds filter to get_themes callable

### Deprecated
- Removed Heartbeat by hoisting it into Connection.

## [1.30.8] - 2022-04-19
### Added
- Added get_themes Callable to sync the list of installed themes on a site
- Added get_themes to Sync defaults

### Changed
- PHPCS: Fix `WordPress.Security.ValidatedSanitizedInput`
- Updated package dependencies.

## [1.30.7] - 2022-04-12
### Added
- Adding new site option to be synced.

## [1.30.6] - 2022-04-06
### Changed
- Updated package dependencies.

### Fixed
- Dedicated Sync: Only try to run the sender once if Dedicated Sync is enabled as it has its own requeueing mechanism.

## [1.30.5] - 2022-03-29
### Changed
- Microperformance: Use === null instead of is_null

## [1.30.4] - 2022-03-23
### Changed
- Enable syncing of dedicated_sync_enabled Sync setting

### Fixed
- Dedicated Sync: Allow spawning request with expired Retry-After

## [1.30.3] - 2022-03-15
### Changed
- Search Sync Settings :: Add ETB taxonomy to allow list.

## [1.30.2] - 2022-03-08
### Changed
- Disallow syncing of _term_meta post_type

## [1.30.1] - 2022-03-02
### Added
- Dedicated Sync flow: Allow enabling or disabling via WPCOM response header

## [1.30.0] - 2022-02-22
### Added
- Add Sync dedicated request flow.

### Changed
- Updated package dependencies.

## [1.29.2] - 2022-02-09
### Added
- Allow sync package consumers to provide custom data settings.

### Fixed
- Fixed some new PHPCS warnings.

## [1.29.1] - 2022-02-02
### Changed
- Updated package dependencies.

## [1.29.0] - 2022-01-25
### Added
- Jetpack Search: update the allowed post meta when search is active to include all indexable meta.

## [1.28.2] - 2022-01-18
### Changed
- Updated package dependencies.

## [1.28.1] - 2022-01-13
### Changed
- Updated package dependencies.

## [1.28.0] - 2022-01-04
### Changed
- Listener: Do not enqueue actions when the site is disconnected
- Switch to pcov for code coverage.
- Theme deletions: rely on Core WP hook now that the package requires WP 5.8.
- Updated package dependencies
- Updated package textdomain from `jetpack` to `jetpack-sync`.

## [1.27.6] - 2021-12-14
### Changed
- Updated package dependencies.

## [1.27.5] - 2021-11-30
### Changed
- Updated package dependencies.

## [1.27.4] - 2021-11-23
### Changed
- Updated package dependencies.

## [1.27.3] - 2021-11-16
### Changed
- Actions: add the do_only_first_initial_sync method which starts an initial sync only when one hasn't already been done

## [1.27.2] - 2021-11-09
### Added
- Constants: Now syncing Atomic platform constant

### Changed
- Full Sync : limit included users to contributors and above (based on wp_user_limit)
- Updated package dependencies.
- User Checksums - limit scope to users with wp_user_level > 0

### Fixed
- Fix PHP 8.1 deprecation warnings.

## [1.27.1] - 2021-11-02
### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [1.27.0] - 2021-10-26
### Added
- Added the _wpas_feature_enabled meta key to the sync list
- Sync Error Log to capture failed sync requests.

### Fixed
- Check the return value of get_comment() before to use it.
- Increase send timeout to 20 seconds allowing capture of WP.com 408 responses.

## [1.26.4] - 2021-10-13
### Changed
- Sync Checksums: Convert text fields to latin1 before generating checksum.
- Updated package dependencies.

### Fixed
- Sync Checksums - Update distinct clause to use $wpdb-> table names to accouunt for differences in prefixes.

## [1.26.3] - 2021-10-12
### Changed
- Updated package dependencies

### Removed
- Remove initialization of the identity-crisis package. That will be handled by the Config package.

### Fixed
- Reduce transient expiration for how often we check the state of the queue.
- Sync Checksums - exclude locale from checksum if same as site setting
- Sync Checksums - use distinct query when calculating count of Term Relationships

## [1.26.2] - 2021-09-28
### Added
- Add support for checksumming user-related tabled: wp_users and wp_usermeta

### Changed
- Update annotations versions.
- Updated package dependencies.

### Fixed
- Resolve indirect modification notice.
- Sync Checksums: utilize distinct clause in term counts.
- Sync Queue: better handling of serialization issues and empty actions.

## [1.26.1] - 2021-09-03
### Fixed
- Add better checks if the WooCommerce tables should be enabled for checksum/fix.
- Prevent PHP notices on queue_pull if all args are not set.

## [1.26.0] - 2021-08-30
### Added
- Add support for WooCommerce table to the checksum/fix process.
- Enable support for utf8 conversion during checksum calculation.

### Changed
- Don't run composer install on regular phpunit script
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).

### Fixed
- Sync Checksums - ensure last object is included in histogram

## [1.25.0] - 2021-08-12
### Added
- Add package version tracking.
- Add `wpcom_is_fse_activated` to sync list
- Made /sync/object endpoint accessible over POST, not only GET, to allow fetching more items in a single request.

## [1.24.2] - 2021-08-02

- Reverted: Sync option for the Carousel to display colorized slide background.

## [1.24.1] - 2021-07-29
### Changed
- Utilize an import for WP_Error in all instances.

### Fixed
- Fixed unqualified WP_Error use in the Rest_Sender class.

## [1.24.0] - 2021-07-27
### Added
- Add a package version constant.
- Add Full Site Editing support to callback options.
- Sync option for the Carousel to display colorized slide background.

### Fixed
- Update Sender so it adheres to max upload bytes when not encoding items.

## [1.23.3] - 2021-07-16
### Fixed
- Update Options module to return jetpack_sync_settings_* values from the Settings class vs direct option lookup.

## [1.23.2] - 2021-07-13
### Changed
- Updated package dependencies.

### Fixed
- Performance of Sync checksums degraded with the update to correlated subquery. This restricts its usage to term_taxonomy joins only."

## [1.23.1] - 2021-07-01
### Changed
- Checksum parent_table joins need distinct selection to account for possibility of multiple rows.

### Fixed
- Update term_taxonomy checksum query to an allowed list vs disallowed

## [1.23.0] - 2021-06-29
### Added
- Add jetpack_idc_disonnect action to clear Sync options on disconnect.
- Add support to callables to sync/object endpoint.
- Enable sync/object endpoint support for theme-info.
- Enhance updates module to support get_objects_by_id.
- Expand sync/object to support constants.
- Extend sync/object to support callables.
- Implement v4 REST endpoints.
- Initialize the IDC package in the Sync package.

### Removed
- Remove product_cat from blocked taxonomies

## [1.22.0] - 2021-06-15
### Changed
- Sync: Adding the Identity_Crisis package.
- Updated package dependencies.

### Deprecated
- Deprecated URL methods in `Automattic\Jetpack\Sync\Functions` in favor of `Automattic\Jetpack\Connection\Urls`.

## [1.21.3] - 2021-05-25
### Changed
- Performance: If no Full Sync is in process early return before we update options.

### Fixed
- Janitorial: avoid PHP notices in some edge-cases
- Update Meta Module so get_object_by_id returns all meta values.

## [1.21.2] - 2021-04-27
### Added
- Added the password-checker package the the Sync package composer.json file.

### Changed
- Updated package dependencies.

### Fixed
- Sync: removed references to the JETPACK__PLUGIN_DIR constant.
- Sync Checksums : updated postmeta range query performance #19337.

## [1.21.1] - 2021-03-30
### Added
- Composer alias for dev-master, to improve dependencies
- Implement a 60 second back-off for non-200 respones, if no retry-after header is present in the response.
- Impose a max limit of 2MB on post meta values that are synced.
- Impose a max limit of 5MB on post_content that can be synced.

### Changed
- Sync: Use the new Password_Checker package instead of Jetpack_Password_Checker.
- Update package dependencies.
- Use the Heartbeat package to generate the stats array

### Fixed
- Migrate locks to update_option to avaoid memcache inconsistencies that can be introduced by delete_option usage.
- Update Sync Queue so that serialize is wrapped to catch errors

## [1.21.0] - 2021-02-23

- General: update WordPress version requirements to WP 5.6
- Update Checksums to support blacklisted taxonomies.
- Refactor Jetpack callables into the plugin using existing filter jetpack_sync_callable_whitelist
- Wrap call_user_func in is_callable so that we don't trigger warnings for callables that don't exist.
- Sync: Trigger initial sync on jetpack_site_registered
- Update Comments checksum field to comment_date_gmt. We cannot use comment_content directly due to charset/filters.
- Deprecate jetpack_json_wrap
- Remove Sync's usage of wp_startswith

## [1.20.2] - 2021-02-08

- Update dependencies to latest stable

## [1.20.1] - 2021-01-28

- Update dependencies to latest stable

## [1.20.0] - 2021-01-26

- Sync Concurrency / Race Conditions
- Sync: Prevent an PHP warning
- Jetpack Sync: Checksums: Use a better way to fetch and validate fields against table
- Add mirror-repo information to all current composer packages
- Full Sync :: Reduce Concurrency.
- Monorepo: Reorganize all projects
- Various PHPCS and Cleanup

## [1.19.4] - 2021-01-18

- Update dependencies to latest stable

## [1.19.3] - 2021-01-18

- Full Sync :: Reduce Concurrency.

## [1.19.2] - 2020-12-21

- Update the do_full_sync function to early return if we are in SYNC READ ONLY mode.
- Return an empty array if the specified range is empty. (It was returning the checksum for the WHOLE dataset).

## [1.19.1] - 2020-12-17

## [1.19.0] - 2020-12-17

- sync: Improve sync checksum algorithm and endpoints
- wp_get_environment_type as callable.
- Disallow amp_validated_url as it is not site content but instead validation errors for amp mark-up.
- Whitelist (allow) jetpack_sync_settings_* options to be synced
- Re-order Sync default option whitelist (allowlist)

## [1.18.1] - 2020-11-24

- Version packages for release

## [1.18.0] - 2020-11-24

- Migrate jetpack_published_post to wp_after_insert_post hook
- Check  value to determine if we should enable sync after an action enqueuement.
- General: update minimum required version to WordPress 5.5
- Fix remaining phpcs warnings in most of requirelist
- Update access of comment_status_to_approval_value to allow extension.
- Update get_term Replicastore function to handle term_taxonomy_id option
- Update get_terms to utilize ensure_taxonomy so that the Taxonomy is registered.
- Addtion of note on explict return of null instead of false if option not found.
- Alignment of comment_status_to_approval_value function. Addition of post-trashed status and cleanup of cases.
- Alignment with implemenations. Call ensure_taxonomy to ensure Taxonomies have been initialized.
- Call ensure_taxonomy within get_object_terms so that the taxonomy is registered before action is performed.
- Updated PHPCS: Packages and Debugger

## [1.17.2] - 2020-11-05

- Update dependencies to latest stable

## [1.17.1] - 2020-10-29

- Update dependencies to latest stable

## [1.17.0] - 2020-10-27

- WPCOM Block Editor: Update meta key name
- Resolve PHP Warning with array_filter usage in sync of action_links.
- Sync: Seperate theme data ( name, version, slug and uri) from theme support data
- Replaced intval() with (int) as part of issue #17432.
- Replaced strval() with type casting (string) as part of issue #17432.
- Replaced floatval() with type cast (float) as part of issue #17432.
- Make XMLRPC methods available for blog token

## [1.16.4] - 2020-10-14

- Update dependencies to latest stable

## [1.16.3] - 2020-10-09

- Update dependencies to latest stable

## [1.16.2] - 2020-10-06

- Update dependencies to latest stable

## [1.16.1] - 2020-10-01

- Update dependencies to latest stable

## [1.16.0] - 2020-09-29

- Publicize: Allow publishing a post as a Twitter thread.
- props @jmdodd - filter out set_object_terms actions that don't perform any update. Includes unit tests.
- Sort Arrays by keys before generating callable checksums
- Packages: avoid PHPCS warnings
- Adding 'review' to whitelisted comment types
- Disable Sync sending on Backup API Requests
- Sync: stop trying to check for edit_comment capability
- Added options to sync wc whitelist
- Sync: Improve theme support syncing

## [1.15.1] - 2020-09-09

- Update dependencies to latest stable

## [1.15.0] - 2020-08-26

- Sync: add Creative Mail configuration option to synced options
- Extend sync_status endpoint with optional debug_details field
- REST API endpoints: expand management endpoints
- Sync: Fix nonce action string in theme edit sync
- WP 5.5 Compat: Align Jetpack and Core's plugin autoupdates
- use current user token to updateRole request
- Resolve Sync Errors from empty edge case and WP.com returning concurrent_request_error
- Rework Sender to properly return state during do_full_sync

## [1.14.4] - 2020-08-10

- WP 5.5 Compat: Align Jetpack and Core's plugin autoupdates

## [1.14.3] - 2020-08-10

- Update dependencies to latest stable

## [1.14.2] - 2020-08-10

- Update dependencies to latest stable

## [1.14.1] - 2020-08-10

- Resolve Sync Errors from empty edge case and WP.com returning concurrent_request_error

## [1.14.0] - 2020-07-28

- Core Compat: Site Environment
- Unit Tests: fix tests according to changes in Core
- Utilize the blog token vs master user token to send sync actions.

## [1.13.2] - 2020-07-06

- Update dependencies to latest stable

## [1.13.1] - 2020-07-01

- Update dependencies to latest stable

## [1.13.0] - 2020-06-30

- Block Flamingo Plugin post types in Jetpack Sync
- Explicit single execution of do_full_sync from cron
- Update  to reference the property defined in the Jetpack Connection Manager class
- PHPCS: Clean up the packages
- WordAds: Add consent support for California Consumer Privacy Act (CCPA)
- Sync: Add additional support for theme_support_whitelist

## [1.12.4] - 2020-06-02

- Revert "Fix `jetpack sync start` CLI command (#16010)"

## [1.12.3] - 2020-06-01

- Update dependencies to latest stable

## [1.12.2] - 2020-06-01

- Fix `jetpack sync start` CLI command

## [1.12.1] - 2020-05-29

- Sync: Add additional support for theme_support_whitelist

## [1.12.0] - 2020-05-26

- Update ReplicaStore to call clean_comment_cache when comments are upserted or a reset is perofrmed.
- Store the list of active plugins that uses connection in an option
- Jetpack Sync :: Alternate non-blocking flow
- Settings - Writing: add a toggle to Carousel so users can hide comment area
- Sender needs to load consistently utilizing  logic
- Always delete items from the queue even if the buffer is no longer checked out.
- Update the  hook of Sync's Comment module to not send meta actions when the comment_type is not whitelisted.
- Sync Comments apply whitelist to all actions

## [1.11.0] - 2020-04-28

- Correct inline documentation "Array" type
- Filter out blacklisted post_types for deleted_post actions.
- Publicize: Add jetpack_publicize_options
- Blacklisting Post Types from Sync
- Comments: update default comment type
- Jetpack Sync: Split `jetpack_post_meta_batch_delete` in action to be called in chunks of 100 items, compared to all at once.
- Update Sync limits based on analysis of data loss events.

## [1.10.0] - 2020-03-31

- Update dependencies to latest stable

## [1.9.0] - 2020-03-31

- Debugger: Add sync health progress bar
- Add main network WPCOM blog ID to sync functions
- Masterbar: send wpcom user ID to wpcom when attempting to log…
- Sync: a better readme

## [1.8.0] - 2020-02-25

- Minileven: add options back  as they still exist on sites
- Sync: add queue size to actions
- Mobile Theme: remove feature

## [1.7.6] - 2020-02-14

- get_sync_status does not properly account for unexpected states.

## [1.7.5] - 2020-02-14

- Empty Helper function for checkin handler
- Sync Health: fix excessive data loss reports
- Initial Sync Health Status Class and Data Loss Handler
- Stop REST API Log entries from being synced

## [1.7.4+vip] - 2020-02-14

- Empty Helper function for checkin handler

## [1.7.4] - 2020-01-23

- Sync Chunk Keys need to be unique

## [1.7.3] - 2020-01-20

- Sync: ensure we run the initial sync on new connections

## [1.7.2] - 2020-01-17

- Sync Package: use Full_Sync_Immediately by default
- Adding new managed WordPress hosts to be identified in class-functions.php.

## [1.7.1] - 2020-01-14

- Packages: Various improvements for wp.com or self-contained consumers

## [1.7.0] - 2020-01-14

- Trying to add deterministic initialization.

## [1.6.3] - 2020-01-07

- Fix git history.

## [1.6.2] - 2019-12-31

- Sync: Remove DEFAULT_SYNC_MODULES legacy map
- Connection: Loose Comparison for Port Number in Signatures

## [1.6.1] - 2019-12-13

- tweak default sync settings

## [1.6.0] - 2019-12-02

- Sync: Full Sync: Send immediately.

## [1.5.1] - 2019-11-26

- Marked the xmlrpc_api_url method as deprecated.

## [1.5.0] - 2019-11-25

- Remove sync settings cache

## [1.4.0] - 2019-11-19

- Full Sync: Don't allow more than one request to enqueue
- Sync: Update Max Int

## [1.3.4] - 2019-11-08

- Packages: Use classmap instead of PSR-4

## [1.3.3] - 2019-11-08

- Deprecate Jetpack::is_development_mode() in favor of the packaged Status()-&gt;is_development_mode()

## [1.3.2] - 2019-11-01

- Full Sync updates to allow full enqueuing of chunks.

## [1.3.1] - 2019-10-29

- PHPCS: Rest of the packages

## [1.3.0] - 2019-10-29

- Sync: Checkout Endpoint: Add `pop` argument 😱

## [1.2.1] - 2019-10-28

- Sync: Add Settings to enable/disable the sender for a particular queue

## [1.2.0] - 2019-10-24

- Sync: Fix how we enqueue term_relationships on full sync 🏝
- WP 5.3: Use modern wp_timezone
- Check for last_error when enqueuing IDs

## [1.1.1] - 2019-10-23

- Use spread operator instead of func_get_args

## [1.1.0] - 2019-10-07

- Sync: Ensure a post object is returned
- PHPCS: Sync Functions
- Sync: Bail initial sync if there is an ongoing full sync

## [1.0.2] - 2019-09-25

- Sync: Only allow white listed comment types to be inserted.
- Sync: Move sync_object XML-RPC method from connection to sync
- Sync: do not sync comments made via Action Scheduler
- Docs: Unify usage of @package phpdoc tags

## [1.0.1] - 2019-09-14

## 1.0.0 - 2019-09-14

- Packages: Move sync to a classmapped package

[1.47.8]: https://github.com/Automattic/jetpack-sync/compare/v1.47.7...v1.47.8
[1.47.7]: https://github.com/Automattic/jetpack-sync/compare/v1.47.6...v1.47.7
[1.47.6]: https://github.com/Automattic/jetpack-sync/compare/v1.47.5...v1.47.6
[1.47.5]: https://github.com/Automattic/jetpack-sync/compare/v1.47.4...v1.47.5
[1.47.4]: https://github.com/Automattic/jetpack-sync/compare/v1.47.3...v1.47.4
[1.47.3]: https://github.com/Automattic/jetpack-sync/compare/v1.47.2...v1.47.3
[1.47.2]: https://github.com/Automattic/jetpack-sync/compare/v1.47.1...v1.47.2
[1.47.1]: https://github.com/Automattic/jetpack-sync/compare/v1.47.0...v1.47.1
[1.47.0]: https://github.com/Automattic/jetpack-sync/compare/v1.46.1...v1.47.0
[1.46.1]: https://github.com/Automattic/jetpack-sync/compare/v1.46.0...v1.46.1
[1.46.0]: https://github.com/Automattic/jetpack-sync/compare/v1.45.0...v1.46.0
[1.45.0]: https://github.com/Automattic/jetpack-sync/compare/v1.44.2...v1.45.0
[1.44.2]: https://github.com/Automattic/jetpack-sync/compare/v1.44.1...v1.44.2
[1.44.1]: https://github.com/Automattic/jetpack-sync/compare/v1.44.0...v1.44.1
[1.44.0]: https://github.com/Automattic/jetpack-sync/compare/v1.43.2...v1.44.0
[1.43.2]: https://github.com/Automattic/jetpack-sync/compare/v1.43.1...v1.43.2
[1.43.1]: https://github.com/Automattic/jetpack-sync/compare/v1.43.0...v1.43.1
[1.43.0]: https://github.com/Automattic/jetpack-sync/compare/v1.42.0...v1.43.0
[1.42.0]: https://github.com/Automattic/jetpack-sync/compare/v1.41.0...v1.42.0
[1.41.0]: https://github.com/Automattic/jetpack-sync/compare/v1.40.3...v1.41.0
[1.40.3]: https://github.com/Automattic/jetpack-sync/compare/v1.40.2...v1.40.3
[1.40.2]: https://github.com/Automattic/jetpack-sync/compare/v1.40.1...v1.40.2
[1.40.1]: https://github.com/Automattic/jetpack-sync/compare/v1.40.0...v1.40.1
[1.40.0]: https://github.com/Automattic/jetpack-sync/compare/v1.39.0...v1.40.0
[1.39.0]: https://github.com/Automattic/jetpack-sync/compare/v1.38.4...v1.39.0
[1.38.4]: https://github.com/Automattic/jetpack-sync/compare/v1.38.3...v1.38.4
[1.38.3]: https://github.com/Automattic/jetpack-sync/compare/v1.38.2...v1.38.3
[1.38.2]: https://github.com/Automattic/jetpack-sync/compare/v1.38.1...v1.38.2
[1.38.1]: https://github.com/Automattic/jetpack-sync/compare/v1.38.0...v1.38.1
[1.38.0]: https://github.com/Automattic/jetpack-sync/compare/v1.37.1...v1.38.0
[1.37.1]: https://github.com/Automattic/jetpack-sync/compare/v1.37.0...v1.37.1
[1.37.0]: https://github.com/Automattic/jetpack-sync/compare/v1.36.1...v1.37.0
[1.36.1]: https://github.com/Automattic/jetpack-sync/compare/v1.36.0...v1.36.1
[1.36.0]: https://github.com/Automattic/jetpack-sync/compare/v1.35.2...v1.36.0
[1.35.2]: https://github.com/Automattic/jetpack-sync/compare/v1.35.1...v1.35.2
[1.35.1]: https://github.com/Automattic/jetpack-sync/compare/v1.35.0...v1.35.1
[1.35.0]: https://github.com/Automattic/jetpack-sync/compare/v1.34.0...v1.35.0
[1.34.0]: https://github.com/Automattic/jetpack-sync/compare/v1.33.1...v1.34.0
[1.33.1]: https://github.com/Automattic/jetpack-sync/compare/v1.33.0...v1.33.1
[1.33.0]: https://github.com/Automattic/jetpack-sync/compare/v1.32.0...v1.33.0
[1.32.0]: https://github.com/Automattic/jetpack-sync/compare/v1.31.1...v1.32.0
[1.31.1]: https://github.com/Automattic/jetpack-sync/compare/v1.31.0...v1.31.1
[1.31.0]: https://github.com/Automattic/jetpack-sync/compare/v1.30.8...v1.31.0
[1.30.8]: https://github.com/Automattic/jetpack-sync/compare/v1.30.7...v1.30.8
[1.30.7]: https://github.com/Automattic/jetpack-sync/compare/v1.30.6...v1.30.7
[1.30.6]: https://github.com/Automattic/jetpack-sync/compare/v1.30.5...v1.30.6
[1.30.5]: https://github.com/Automattic/jetpack-sync/compare/v1.30.4...v1.30.5
[1.30.4]: https://github.com/Automattic/jetpack-sync/compare/v1.30.3...v1.30.4
[1.30.3]: https://github.com/Automattic/jetpack-sync/compare/v1.30.2...v1.30.3
[1.30.2]: https://github.com/Automattic/jetpack-sync/compare/v1.30.1...v1.30.2
[1.30.1]: https://github.com/Automattic/jetpack-sync/compare/v1.30.0...v1.30.1
[1.30.0]: https://github.com/Automattic/jetpack-sync/compare/v1.29.2...v1.30.0
[1.29.2]: https://github.com/Automattic/jetpack-sync/compare/v1.29.1...v1.29.2
[1.29.1]: https://github.com/Automattic/jetpack-sync/compare/v1.29.0...v1.29.1
[1.29.0]: https://github.com/Automattic/jetpack-sync/compare/v1.28.2...v1.29.0
[1.28.2]: https://github.com/Automattic/jetpack-sync/compare/v1.28.1...v1.28.2
[1.28.1]: https://github.com/Automattic/jetpack-sync/compare/v1.28.0...v1.28.1
[1.28.0]: https://github.com/Automattic/jetpack-sync/compare/v1.27.6...v1.28.0
[1.27.6]: https://github.com/Automattic/jetpack-sync/compare/v1.27.5...v1.27.6
[1.27.5]: https://github.com/Automattic/jetpack-sync/compare/v1.27.4...v1.27.5
[1.27.4]: https://github.com/Automattic/jetpack-sync/compare/v1.27.3...v1.27.4
[1.27.3]: https://github.com/Automattic/jetpack-sync/compare/v1.27.2...v1.27.3
[1.27.2]: https://github.com/Automattic/jetpack-sync/compare/v1.27.1...v1.27.2
[1.27.1]: https://github.com/Automattic/jetpack-sync/compare/v1.27.0...v1.27.1
[1.27.0]: https://github.com/Automattic/jetpack-sync/compare/v1.26.4...v1.27.0
[1.26.4]: https://github.com/Automattic/jetpack-sync/compare/v1.26.3...v1.26.4
[1.26.3]: https://github.com/Automattic/jetpack-sync/compare/v1.26.2...v1.26.3
[1.26.2]: https://github.com/Automattic/jetpack-sync/compare/v1.26.1...v1.26.2
[1.26.1]: https://github.com/Automattic/jetpack-sync/compare/v1.26.0...v1.26.1
[1.26.0]: https://github.com/Automattic/jetpack-sync/compare/v1.25.0...v1.26.0
[1.25.0]: https://github.com/Automattic/jetpack-sync/compare/v1.24.2...v1.25.0
[1.24.2]: https://github.com/Automattic/jetpack-sync/compare/v1.24.1...v1.24.2
[1.24.1]: https://github.com/Automattic/jetpack-sync/compare/v1.24.0...v1.24.1
[1.24.0]: https://github.com/Automattic/jetpack-sync/compare/v1.23.3...v1.24.0
[1.23.3]: https://github.com/Automattic/jetpack-sync/compare/v1.23.2...v1.23.3
[1.23.2]: https://github.com/Automattic/jetpack-sync/compare/v1.23.1...v1.23.2
[1.23.1]: https://github.com/Automattic/jetpack-sync/compare/v1.23.0...v1.23.1
[1.23.0]: https://github.com/Automattic/jetpack-sync/compare/v1.22.0...v1.23.0
[1.22.0]: https://github.com/Automattic/jetpack-sync/compare/v1.21.3...v1.22.0
[1.21.3]: https://github.com/Automattic/jetpack-sync/compare/v1.21.2...v1.21.3
[1.21.2]: https://github.com/Automattic/jetpack-sync/compare/v1.21.1...v1.21.2
[1.21.1]: https://github.com/Automattic/jetpack-sync/compare/v1.21.0...v1.21.1
[1.21.0]: https://github.com/Automattic/jetpack-sync/compare/v1.20.2...v1.21.0
[1.20.2]: https://github.com/Automattic/jetpack-sync/compare/v1.20.1...v1.20.2
[1.20.1]: https://github.com/Automattic/jetpack-sync/compare/v1.20.0...v1.20.1
[1.20.0]: https://github.com/Automattic/jetpack-sync/compare/v1.19.4...v1.20.0
[1.19.4]: https://github.com/Automattic/jetpack-sync/compare/v1.19.3...v1.19.4
[1.19.3]: https://github.com/Automattic/jetpack-sync/compare/v1.19.2...v1.19.3
[1.19.2]: https://github.com/Automattic/jetpack-sync/compare/v1.19.1...v1.19.2
[1.19.1]: https://github.com/Automattic/jetpack-sync/compare/v1.19.0...v1.19.1
[1.19.0]: https://github.com/Automattic/jetpack-sync/compare/v1.18.1...v1.19.0
[1.18.1]: https://github.com/Automattic/jetpack-sync/compare/v1.18.0...v1.18.1
[1.18.0]: https://github.com/Automattic/jetpack-sync/compare/v1.17.2...v1.18.0
[1.17.2]: https://github.com/Automattic/jetpack-sync/compare/v1.17.1...v1.17.2
[1.17.1]: https://github.com/Automattic/jetpack-sync/compare/v1.17.0...v1.17.1
[1.17.0]: https://github.com/Automattic/jetpack-sync/compare/v1.16.4...v1.17.0
[1.16.4]: https://github.com/Automattic/jetpack-sync/compare/v1.16.3...v1.16.4
[1.16.3]: https://github.com/Automattic/jetpack-sync/compare/v1.16.2...v1.16.3
[1.16.2]: https://github.com/Automattic/jetpack-sync/compare/v1.16.1...v1.16.2
[1.16.1]: https://github.com/Automattic/jetpack-sync/compare/v1.16.0...v1.16.1
[1.16.0]: https://github.com/Automattic/jetpack-sync/compare/v1.15.1...v1.16.0
[1.15.1]: https://github.com/Automattic/jetpack-sync/compare/v1.15.0...v1.15.1
[1.15.0]: https://github.com/Automattic/jetpack-sync/compare/v1.14.4...v1.15.0
[1.14.4]: https://github.com/Automattic/jetpack-sync/compare/v1.14.3...v1.14.4
[1.14.3]: https://github.com/Automattic/jetpack-sync/compare/v1.14.2...v1.14.3
[1.14.2]: https://github.com/Automattic/jetpack-sync/compare/v1.14.1...v1.14.2
[1.14.1]: https://github.com/Automattic/jetpack-sync/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/Automattic/jetpack-sync/compare/v1.13.2...v1.14.0
[1.13.2]: https://github.com/Automattic/jetpack-sync/compare/v1.13.1...v1.13.2
[1.13.1]: https://github.com/Automattic/jetpack-sync/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/Automattic/jetpack-sync/compare/v1.12.4...v1.13.0
[1.12.4]: https://github.com/Automattic/jetpack-sync/compare/v1.12.3...v1.12.4
[1.12.3]: https://github.com/Automattic/jetpack-sync/compare/v1.12.2...v1.12.3
[1.12.2]: https://github.com/Automattic/jetpack-sync/compare/v1.12.1...v1.12.2
[1.12.1]: https://github.com/Automattic/jetpack-sync/compare/v1.12.0...v1.12.1
[1.12.0]: https://github.com/Automattic/jetpack-sync/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/Automattic/jetpack-sync/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/Automattic/jetpack-sync/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/Automattic/jetpack-sync/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/Automattic/jetpack-sync/compare/v1.7.6...v1.8.0
[1.7.6]: https://github.com/Automattic/jetpack-sync/compare/v1.7.5...v1.7.6
[1.7.5]: https://github.com/Automattic/jetpack-sync/compare/v1.7.4+vip...v1.7.5
[1.7.4+vip]: https://github.com/Automattic/jetpack-sync/compare/v1.7.4...v1.7.4+vip
[1.7.4]: https://github.com/Automattic/jetpack-sync/compare/v1.7.3...v1.7.4
[1.7.3]: https://github.com/Automattic/jetpack-sync/compare/v1.7.2...v1.7.3
[1.7.2]: https://github.com/Automattic/jetpack-sync/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-sync/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-sync/compare/v1.6.3...v1.7.0
[1.6.3]: https://github.com/Automattic/jetpack-sync/compare/v1.6.2...v1.6.3
[1.6.2]: https://github.com/Automattic/jetpack-sync/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/Automattic/jetpack-sync/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-sync/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/Automattic/jetpack-sync/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Automattic/jetpack-sync/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Automattic/jetpack-sync/compare/v1.3.4...v1.4.0
[1.3.4]: https://github.com/Automattic/jetpack-sync/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/Automattic/jetpack-sync/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/Automattic/jetpack-sync/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/Automattic/jetpack-sync/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Automattic/jetpack-sync/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/Automattic/jetpack-sync/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Automattic/jetpack-sync/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/Automattic/jetpack-sync/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Automattic/jetpack-sync/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Automattic/jetpack-sync/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Automattic/jetpack-sync/compare/v1.0.0...v1.0.1
