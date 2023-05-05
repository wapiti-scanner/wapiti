# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.51.7] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]

## [1.51.6] - 2023-04-04
### Changed
- Updated package dependencies. [#29854]

### Removed
- Do not attempt to load non minified files since they are not shipped with the package anymore. [#29864]

## [1.51.5] - 2023-03-29
### Changed
- Minor internal updates.

## [1.51.4] - 2023-03-28
### Changed
- Minor internal updates.

## [1.51.3] - 2023-03-27
### Fixed
- Fix redirect allow-list for Calypso domain names. [#29671]

## [1.51.2] - 2023-03-20
### Changed
- Updated package dependencies. [#29471]

## [1.51.1] - 2023-03-08
### Changed
- Improve JS code in the connection owner removal notice. [#29087]
- Updated package dependencies. [#29216]

## [1.51.0] - 2023-02-20
### Changed
- Moving deleting connection owner notice from JITM to Connection package. [#28516]

## [1.50.1] - 2023-02-15
### Changed
- Update to React 18. [#28710]

## [1.50.0] - 2023-02-07
### Added
- Call the Licensing package for license verification.

## [1.49.1] - 2023-01-25
### Changed
- Minor internal updates.

## [1.49.0] - 2023-01-11
### Added
- Add new method to get a connected site's blog ID. [#28208]

## [1.48.1] - 2022-12-27
### Removed
- Remove src/js files from final bundle [#27931]

## [1.48.0] - 2022-12-19
### Changed
- Provide user locale when fetching info about connected WordPress.com user. [#27928]
- Update for PHP 8.2 compatibility. [#27949]

### Fixed
- Declare fields for PHP 8.2 compatibility. [#27968]

## [1.47.1] - 2022-12-02
### Changed
- Updated package dependencies. [#27696]

## [1.47.0] - 2022-11-30
### Added
- Added full response logging for failed Sync data requests. [#27644]

## [1.46.4] - 2022-11-22
### Changed
- Updated package dependencies. [#27043]

## [1.46.3] - 2022-11-08
### Changed
- Updated package dependencies. [#27289]

## [1.46.2] - 2022-11-07
### Changed
- Updated package dependencies. [#27278]

## [1.46.1] - 2022-11-01
### Changed
- Updated package dependencies.

## [1.46.0] - 2022-10-25
### Changed
- Use blog token to unlink users from WPCOM. [#26705]

## [1.45.5] - 2022-10-25
### Added
- Connection: expose BlogId in the global state [#26978]

## [1.45.4] - 2022-10-13
### Changed
- Updated package dependencies. [#26791]

## [1.45.3] - 2022-10-05
### Changed
- Updated package dependencies. [#26568]

### Fixed
- Clean connection errors after successful blog token restore. [#26489]

## [1.45.2] - 2022-09-21
### Fixed
- Check request body error type before creating wp error. [#26304]

## [1.45.1] - 2022-09-20
### Fixed
- Rename the initial state key to ensure compatibility with the JS package. [#26259]

## [1.45.0] - 2022-09-08
### Changed
- Add option to JP options [#25979]

## [1.44.0] - 2022-08-29
### Added
- Connection: verify REST API errors.

## [1.43.1] - 2022-08-25
### Changed
- Updated package dependencies. [#25814]

## [1.43.0] - 2022-08-23
### Added
- Added verified errors to the React initial state. [#25628]

### Fixed
- Improved docs. [#25703]

## [1.42.0] - 2022-08-03
### Changed
- Refactoring to remove usage of deprecated methods and method arguments. [#25315]

### Deprecated
- Removed deprecated method calls [#25300]

## [1.41.8] - 2022-07-29

- Updated package dependencies

## [1.41.7] - 2022-07-26
### Changed
- Updated package dependencies. [#25158]

### Fixed
- Tokens: edit return doc to highlight possibility of returning WP_Error. [#25127]

## [1.41.6] - 2022-07-19
### Changed
- Updated package dependencies.

## [1.41.5] - 2022-07-12
### Changed
- Updated package dependencies.

## [1.41.4] - 2022-06-29

- Updated package dependencies.

## [1.41.3] - 2022-06-28
### Fixed
- Connection: fix fatal error due to undefined constant in remote_provision()

## [1.41.2] - 2022-06-28
### Removed
- Removed use of autounit tag [#24845]

## [1.41.1] - 2022-06-21
### Changed
- Renaming master to trunk.
- Renaming `master` references to `trunk`

## [1.41.0] - 2022-06-14
### Changed
- Updated package dependencies. [#24529]

### Fixed
- Fixed old tk_ai regex to accurately match tk_ai ids. [#24697]
- Moved the connection_url_redirect action handling to the connection package. [#24529]

## [1.40.5] - 2022-06-08
### Changed
- Reorder JS imports for `import/order` eslint rule. [#24601]

## [1.40.4] - 2022-05-24
### Added
- Allow plugins to filter the list of available modules. Only activate and consider active modules that are available [#24454]

## [1.40.3] - 2022-05-19
### Added
- PHPCS updates. [#24418]

## [1.40.2] - 2022-05-18
### Changed
- Updated package dependencies [#24372]

### Fixed
- Fix new PHPCS sniffs. [#24366]

## [1.40.1] - 2022-05-10
### Added
- Bundle and transpile JavaScript with Webpack. [#24216]

### Changed
- Deprecate soft disconnect [#24105]

## [1.40.0] - 2022-05-04
### Added
- Connection: Expose wpVersion and siteSuffix in the global initial state var [#24137]

### Deprecated
- Moved the options class into Connection. [#24095]

## [1.39.2] - 2022-05-19
### Added
- PHPCS updates.

## [1.39.1] - 2022-04-27
### Fixed
- Reverts soft disconnect deprecation

## [1.39.0] - 2022-04-26
### Changed
- Make remove_connection a proxy method to ensure all trackings are triggered
- Updated package dependencies.

### Deprecated
- Removed Heartbeat by hoisting it into Connection.

### Removed
- Deprecated Soft disconnect

## [1.38.0] - 2022-04-19
### Added
- Added list of connected list to the connection initial state
- Add token lock functionality.

### Changed
- PHPCS: Fix `WordPress.Security.ValidatedSanitizedInput`

### Deprecated
- Deprecated in-place connection.

## [1.37.6] - 2022-04-12
### Changed
- Updated package dependencies.

## [1.37.5] - 2022-04-06
### Removed
- Removed tracking dependency.

## [1.37.4] - 2022-04-05
### Changed
- Updated package dependencies.

## [1.37.3] - 2022-03-29
### Changed
- Microperformance: Use === null instead of is_null

### Fixed
- Fix regression added to Jetpack webhooks handling

## [1.37.2] - 2022-03-23
### Changed
- Jetpack now relies on Connection Webooks for authorize and authorize_redirect actions

### Removed
- Removed a reference to the terms-of-service package.

## [1.37.1] - 2022-03-15
### Added
- Handle the Authorization Redirect from the Connection package

## [1.37.0] - 2022-03-02
### Added
- Moved the ToS package to Connection.

## [1.36.4] - 2022-02-22
### Changed
- Updated package dependencies.

## [1.36.3] - 2022-02-16
### Added
- Add the 'jetpack_site_before_disconnected' action hook.

## [1.36.2] - 2022-02-09
### Fixed
- Fixed some new PHPCS warnings.

## [1.36.1] - 2022-01-25
### Changed
- Updated package dependencies.

## [1.36.0] - 2022-01-18
### Added
- Debugging: Add a filter to add XDEBUG_PROFILE to requests made to the sandbox.

## [1.35.0] - 2022-01-13
### Changed
- Added user data to initial state

## [1.34.0] - 2022-01-04
### Added
- Jetpack Connection: Added fallback for keeping `jetpack_connection_active_plugins` consistent on WPCOM when Sync is not present.

### Changed
- Switch to pcov for code coverage.
- Updated package dependencies
- Updated package textdomain from `jetpack` to `jetpack-connection`.

## [1.33.0] - 2021-12-14
### Changed
- Jetpack Connection: handle package versions on site registration.

## [1.32.0] - 2021-11-30
### Added
- Added a way to set the has_seen_wc_connection_modal option from the API
- Provides an Initial State that can be used by JS packages

### Changed
- Updated package dependencies.

## [1.31.0] - 2021-11-22
### Added
- Added plugin_slug parameter to the v4/register endpoint

### Changed
- Updated package dependencies

## [1.30.13] - 2021-11-09
### Fixed
- Fix PHP 8.1 deprecation warning.

## [1.30.12] - 2021-11-02
### Added
- Client: add IDC query args to remote requests

### Changed
- Set `convertDeprecationsToExceptions` true in PHPUnit config.
- Update PHPUnit configs to include just what needs coverage rather than include everything then try to exclude stuff that doesn't.

## [1.30.11] - 2021-10-26
### Changed
- Change the error code returned when a remoteRegister XMLRPC call is executed to the more helpful "already_registered" when the blog is already registered
- Updated package dependencies.

## [1.30.10] - 2021-10-19
### Deprecated
- General: remove numerous long-deprecated functions.

### Fixed
- Fix permission check for authorization_url endpoint.

## [1.30.9] - 2021-10-13
### Changed
- Updated package dependencies.

## [1.30.8] - 2021-10-12
### Added
- Add a new action to the Client::remote_request method, jetpack_received_remote_request_response

### Changed
- Updated package dependencies

## [1.30.7] - 2021-10-04
### Added
- Sandbox Server: add the sandbox-server class to the connection package.

## [1.30.6] - 2021-09-30
### Changed
- Moved the Package Tracker execution to the shutdown hook for performance improvement.

## [1.30.5] - 2021-09-28
### Changed
- Package Version Tracker: send package versions to wpcom on the init hook instead of plugins_loaded
- Updated package dependencies.

### Fixed
- Load WordPress's IXR classes on demand.

## [1.30.4] - 2021-09-02
### Fixed
- Remove invalid user token before reconnect.

## [1.30.3] - 2021-08-30
### Added
- Limit repeated failed attempts to update remote DNA package versions.

### Changed
- Make sure generated secrets have the required length
- Remove tracked package versions when disconnecting the site.
- Run composer update on test-php command instead of phpunit
- Tests: update PHPUnit polyfills dependency (yoast/phpunit-polyfills).
- update annotations versions

## [1.30.2] - 2021-08-12
### Added
- Add package version tracking.

## [1.30.1] - 2021-07-27
### Added
- Add a package version constant.

### Changed
- Move connection/data endpoint to Connection package.
- Move site disconnection endpoint to Connection package.

### Fixed
- Fix `@covers` directives in tests.

## [1.30.0] - 2021-07-13
### Added
- Added second parameter to Tokens::get_connected_users to allow any connected user to be returned.

### Changed
- Moved the get_connected_users logic back to the Manager class

## [1.29.0] - 2021-06-29
### Changed
- Implement disconnect_site function.
- Updated package dependencies.

## [1.28.0] - 2021-06-15
### Added
- Added Urls class, migrated from Sync Functions.
- Adding new REST endpoint /jetpack/v4/user-token that allows us to add/update user tokens remotely.
- Add new 'connection/authorize_url' endpoint.
- Adds information received from the server to the register_site REST response.
- Enable site-level authentication (blog token) for REST API endpoints.
- Move 'connection/owner' endpoint to Connection package.

## [1.27.0] - 2021-05-25
### Added
- Add "isUserConnected" to the connection status data.
- Connection: add the default value of JETPACK__WPCOM_JSON_API_BASE to the Connection Utils class.

### Changed
- Connection package independence: Move a Jetpack specfic connection routine out of the package and into the plugin
- Package Independence: Add a filter to the remote_uri returned by remote_register XMLRPC method

### Removed
- Removed "user-less" jargon from code
- Remove do_post_authorization routine and add a hook instead
- Remove onboarding_token logic in the Remote provision XMLRPC method from the Connection package and add it to the Jetpack plugin

### Fixed
- Disconnection flow: disconnect users from WordPress.com before to delete data locally.

## [1.26.0] - 2021-04-27
### Added
- Adds segmentation "from" parameter to the registration flow
- Connection: moving the registration REST endpoint to the package.

### Changed
- Added "userless" parameter to the authorization URL.
- Updated package dependencies.

## [1.25.2] - 2021-04-13
### Fixed
- Connection: nonce cleanup safeguard against accidental option removal.

## [1.25.1] - 2021-04-08
### Fixed
- Avoid determine_current_user going through infinite loops
- Tokens: Fix token validation logic.

## [1.25.0] - 2021-03-30
### Added
- Add new test for blog token health to support user-less sites
- Composer alias for dev-master, to improve dependencies

### Changed
- API Nonces: performance optimization and refactoring
- Replace is_active usage towards gradually deprecating it.
- Do not use is_active to determine the XMLRPC methods that should be registered
- Make connected_plugins REST endpoint available for the Jetpack Debugger
- Move Jetpack specific XMLRPC methods from the Connection package into the plugin
- Update package dependencies.
- User-less connection: Reconnect without asking the user to connect their WPCOM account

### Deprecated
- add deprecation notice and remove user-less check in is_active

### Fixed
- Only check offline mode when needed in map_meta_cap filters
- Use `composer update` rather than `install` in scripts, as composer.lock isn't checked in.

## [1.24.0] - 2021-02-23

- Refactor secrets and tokens
- User-less connection: Restrict first connection to admins only
- Connection: Prevent pointless calls to the test API
- CI: Make tests more generic
- Connection: extracting the Jetpack's authorization webhook
- codesniffer: Update mediawiki-codesniffer dep to v35.0

## [1.23.2] - 2021-02-08

- Connection: Prevent pointless calls to the test API

## [1.23.1] - 2021-01-28

- Update dependencies to latest stable

## [1.23.0] - 2021-01-26

- Sync Concurrency / Race Conditions
- Add mirror-repo information to all current composer packages
- Mirroring: Fix auth, attempt 2
- Monorepo: Reorganize all projects

## [1.22.0] - 2021-01-05

- Connection: setting valid connection owner.
- userless testing mode: do not discard user tokens
- Pin dependencies
- Packages: Update for PHP 8 testing
- Connection: New methods and tests to the manager
- Connection: refreshing connected plugin storage on multisite networks
- Build: migrate from Travis to GH Actions
- fix typos and add section to error handling docs

## [1.21.1] - 2020-11-24

- Version packages for release

## [1.21.0] - 2020-11-24

- Handle empty SERVER_PORT information on signature checks
- Fix remaining phpcs warnings in most of requirelist
- Add the no_user_testing mode
- Clarified error message for non-writable options table.
- Pass HTTP POST when making a wp.com api request

## [1.20.0] - 2020-10-29

- Connection: Plugin Tracking
- Connection Package: Ensure a text/xml header is set
- Updated PHPCS: Packages and Debugger

## [1.19.2] - 2020-11-05

- Pass HTTP POST when making a wp.com api request

## [1.19.1] - 2020-10-29

- Connection: Plugin Tracking

## [1.19.0] - 2020-10-27

- Connection Errors: Tracking additional error data
- Replaced intval() with (int) as part of issue #17432.
- Replaced strval() with type casting (string) as part of issue #17432.
- Connection: Add wp.com function
- Instagram oEmbed: Simplify
- Client: Extract `validate_args_for_wpcom_json_api_request` helper.
- Connection: add the constant filter hooks directly
- Make XMLRPC methods available for blog token
- API Nonces: Revert of the Runtime Cleanup.
- PHPCS: Update directory structure, and modernize class usage
- deprecates JETPACK_MASTER_USER and adds linter
- API: Remove the constant `JETPACK_CLIENT__HTTPS`.

## [1.18.4] - 2020-10-14

- Connection: Add wp.com function

## [1.18.3] - 2020-10-09

- Connection: add the constant filter hooks directly

## [1.18.2] - 2020-10-06

- API Nonces: Revert of the Runtime Cleanup.

## [1.18.1] - 2020-10-01

- deprecates JETPACK_MASTER_USER and adds linter

## [1.18.0] - 2020-09-29

- API Nonces: Runtime cleanup
- Packages: update list of files distributed in production packages
- Connection: Add success message on completed partial reconnection
- Jetpack_IXR_ClientMulticall: Fix sort_calls() producing undefined relative order between equal items
- Connection: Initializing default constants for the REST authorization.
- Trigger action jetpack_user_authorize after we save the token
- Partial reconnect: Cleanup redundant actions
- Signature Class: Adds support for nested query strings

## [1.17.2] - 2020-09-16

- Connection: Initializing default constants for the REST authorization.

## [1.17.1] - 2020-09-09

- Update dependencies to latest stable

## [1.17.0] - 2020-08-26

- Connection: move the rest authentication methods to the connection package
- Connection: use heartbeat to send connected plugins info
- clear xmlrpc error on site disconnect
- add new features to debug helper
- remove no longer needed check
- disable xmlrpc errors out of JP dashboard
- Connection REST API: Unit test for the `remote_authorize` request.
- Simplify error notices for broken connections
- Unit Tests: Fixing a failing `remote_authorize` test.
- Reconnect Process: Partial Reconnect
- Packages: Update filenames after #16810
- CI: Try collect js coverage
- Docker: Add package testing shortcut
- Remove usages of removed HTTP_RAW_POST_DATA
- adds tracking for deleted but active master users
- New class to handle async XML-RPC requests
- Connection Register: Add current user email to connection register request

## [1.15.2] - 2020-08-10

- Connection Register: Add current user email to connection register request

## [1.15.1] - 2020-08-10

- adds tracking for deleted but active master users

## [1.15.0] - 2020-07-28

- Core Compat: Site Environment
- Reconnect Notice: In-place Reconnect
- add messages for some common connection errors
- REST API: Move some endpoints to `jetpack-connection` package.
- REST API: Add permission callback to all that lack one.
- Secondary user in-place connection flow
- Tests: Update WorDBless location
- Connection Errors: Clear when there's a successful request to /sites
- Connection: add unit tests for is_registered
- only display connection errors to allowed users

## [1.14.2] - 2020-07-06

- Connection Errors: Clear when there's a successful request to /sites

## [1.14.1] - 2020-07-01

- only display connection errors to allowed users

## [1.14.0] - 2020-06-30

- Jetpack_XMLRPC_Server: set up jsonAPI and testConnection endpoint when Jetpack is active
- Connection Error Handling
- Connection: Update XMLRPC overload
- Connection: move connection custom caps to the Connection package
- Connection package: Don't throw warnings if the database is corrupted somehow
- Check blog token when computing is_registered
- Connection: add the api_constant filter before setup_xmlrpc_handlers is called
- Connection Package: Soft Disconnects
- Remove usage of the Jetpack_Error class in the connection package
- Connection: Fix issue where ABSPATH not included with register

## [1.13.1] - 2020-06-01

- Connection: Fix issue where ABSPATH not included with register

## [1.13.0] - 2020-05-26

- Store the list of active plugins that uses connection in an option
- Connection: increase timeout on the token request
- Connection Package: Handle disconnections gracefully

## [1.12.0] - 2020-04-28

- Correct inline documentation "Array" type
- Use jp.com redirect in all links
- Docs: Update the Connection Manager namespace, a minor typo
- Connection: add a filter for setting Jetpack api constants

## [1.11.0] - 2020-03-31

- Update dependencies to latest stable

## [1.10.0] - 2020-03-31

- Connection: move post authorization work to package

## [1.9.0] - 2020-02-25

## [1.8.3] - 2020-02-14

## [1.8.2] - 2020-02-12

## [1.8.1] - 2020-02-12

- Added a specific filter to enable iframe authorization API URL.
- Added better defaults for the connection package.

## [1.8.0] - 2020-01-27

- Connection\Utils: Add a new function which provides the Jetpack API version
- Connection\Manager: Use jetpack_master_user class constant

## [1.7.2] - 2020-01-20

- Move connection manager related logic to after plugins_loaded.

## [1.7.1] - 2020-01-14

- Packages: Various improvements for wp.com or self-contained consumers

## [1.7.0] - 2019-11-26

- Connection package: Add new methods to for disconnecting/delet…

## [1.6.1] - 2019-11-25

- Connection: Loose Comparison for Port Number in Signatures

## [1.6.0] - 2019-11-19

## [1.5.0] - 2019-11-15

- Removed Jetpack references in the IXR client.
- Connection: Move get_token() to Connection package

## [1.4.0] - 2019-11-15

- Add connection authentication URL.
- Connection: Move the authorize() method to the connection package
- Connection: Move update_user_token to the Connection package
- Connection: Set the value of user_id in Manager::generate_secrets

## [1.3.1] - 2019-11-08

- Packages: Use classmap instead of PSR-4
- Moved tracking code to the Tracking file.

## [1.3.0] - 2019-11-08

- Move fix_url_for_bad_hosts from Jetpack class to Connection pa…

## [1.2.0] - 2019-11-07

- Connection: call verify_secrets() in verify_action()

## [1.1.0] - 2019-10-31

- Adds filter capability to the api_url method.

## [1.0.7] - 2019-10-28

- Packages: Add gitattributes files to all packages that need th…
- Replace parse_url with wp_parse_url

## [1.0.6] - 2019-10-07

- Update dependency phpcompatibility/phpcompatibility-wp to v2.1.0

## [1.0.5] - 2019-09-26

- XMLRPC: Fires clean_nonce action in all cases

## [1.0.4] - 2019-09-24

- Connection: Make sure port is an integer

## [1.0.3] - 2019-09-23

- Moves unreachable code to where it would be run.
- Connection: Deprecate Manager interface

## [1.0.2] - 2019-09-23

- Connection: Fix all PHPCS errors in the connection package

## [1.0.1] - 2019-09-20

- Various: Remove pre-PHP 5.6 shims and fallbacks
- Store "Assumed site creation date" in transient
- Sync: Move sync_object XML-RPC method from connection to sync
- Connection: Fix PHPCS errors in Jetpack_Signature
- Docs: Unify usage of @package phpdoc tags
- Janitorial: Remove the leading backslash from namespaces

## 1.0.0 - 2019-09-14

- Separate the connection library into its own package.

[1.51.7]: https://github.com/Automattic/jetpack-connection/compare/v1.51.6...v1.51.7
[1.51.6]: https://github.com/Automattic/jetpack-connection/compare/v1.51.5...v1.51.6
[1.51.5]: https://github.com/Automattic/jetpack-connection/compare/v1.51.4...v1.51.5
[1.51.4]: https://github.com/Automattic/jetpack-connection/compare/v1.51.3...v1.51.4
[1.51.3]: https://github.com/Automattic/jetpack-connection/compare/v1.51.2...v1.51.3
[1.51.2]: https://github.com/Automattic/jetpack-connection/compare/v1.51.1...v1.51.2
[1.51.1]: https://github.com/Automattic/jetpack-connection/compare/v1.51.0...v1.51.1
[1.51.0]: https://github.com/Automattic/jetpack-connection/compare/v1.50.1...v1.51.0
[1.50.1]: https://github.com/Automattic/jetpack-connection/compare/v1.50.0...v1.50.1
[1.50.0]: https://github.com/Automattic/jetpack-connection/compare/v1.49.1...v1.50.0
[1.49.1]: https://github.com/Automattic/jetpack-connection/compare/v1.49.0...v1.49.1
[1.49.0]: https://github.com/Automattic/jetpack-connection/compare/v1.48.1...v1.49.0
[1.48.1]: https://github.com/Automattic/jetpack-connection/compare/v1.48.0...v1.48.1
[1.48.0]: https://github.com/Automattic/jetpack-connection/compare/v1.47.1...v1.48.0
[1.47.1]: https://github.com/Automattic/jetpack-connection/compare/v1.47.0...v1.47.1
[1.47.0]: https://github.com/Automattic/jetpack-connection/compare/v1.46.4...v1.47.0
[1.46.4]: https://github.com/Automattic/jetpack-connection/compare/v1.46.3...v1.46.4
[1.46.3]: https://github.com/Automattic/jetpack-connection/compare/v1.46.2...v1.46.3
[1.46.2]: https://github.com/Automattic/jetpack-connection/compare/v1.46.1...v1.46.2
[1.46.1]: https://github.com/Automattic/jetpack-connection/compare/v1.46.0...v1.46.1
[1.46.0]: https://github.com/Automattic/jetpack-connection/compare/v1.45.5...v1.46.0
[1.45.5]: https://github.com/Automattic/jetpack-connection/compare/v1.45.4...v1.45.5
[1.45.4]: https://github.com/Automattic/jetpack-connection/compare/v1.45.3...v1.45.4
[1.45.3]: https://github.com/Automattic/jetpack-connection/compare/v1.45.2...v1.45.3
[1.45.2]: https://github.com/Automattic/jetpack-connection/compare/v1.45.1...v1.45.2
[1.45.1]: https://github.com/Automattic/jetpack-connection/compare/v1.45.0...v1.45.1
[1.45.0]: https://github.com/Automattic/jetpack-connection/compare/v1.44.0...v1.45.0
[1.44.0]: https://github.com/Automattic/jetpack-connection/compare/v1.43.1...v1.44.0
[1.43.1]: https://github.com/Automattic/jetpack-connection/compare/v1.43.0...v1.43.1
[1.43.0]: https://github.com/Automattic/jetpack-connection/compare/v1.42.0...v1.43.0
[1.42.0]: https://github.com/Automattic/jetpack-connection/compare/v1.41.8...v1.42.0
[1.41.8]: https://github.com/Automattic/jetpack-connection/compare/v1.41.7...v1.41.8
[1.41.7]: https://github.com/Automattic/jetpack-connection/compare/v1.41.6...v1.41.7
[1.41.6]: https://github.com/Automattic/jetpack-connection/compare/v1.41.5...v1.41.6
[1.41.5]: https://github.com/Automattic/jetpack-connection/compare/v1.41.4...v1.41.5
[1.41.4]: https://github.com/Automattic/jetpack-connection/compare/v1.41.3...v1.41.4
[1.41.3]: https://github.com/Automattic/jetpack-connection/compare/v1.41.2...v1.41.3
[1.41.2]: https://github.com/Automattic/jetpack-connection/compare/v1.41.1...v1.41.2
[1.41.1]: https://github.com/Automattic/jetpack-connection/compare/v1.41.0...v1.41.1
[1.41.0]: https://github.com/Automattic/jetpack-connection/compare/v1.40.5...v1.41.0
[1.40.5]: https://github.com/Automattic/jetpack-connection/compare/v1.40.4...v1.40.5
[1.40.4]: https://github.com/Automattic/jetpack-connection/compare/v1.40.3...v1.40.4
[1.40.3]: https://github.com/Automattic/jetpack-connection/compare/v1.40.2...v1.40.3
[1.40.2]: https://github.com/Automattic/jetpack-connection/compare/v1.40.1...v1.40.2
[1.40.1]: https://github.com/Automattic/jetpack-connection/compare/v1.40.0...v1.40.1
[1.40.0]: https://github.com/Automattic/jetpack-connection/compare/v1.39.1...v1.40.0
[1.39.2]: https://github.com/Automattic/jetpack-connection/compare/v1.39.1...v1.39.2
[1.39.1]: https://github.com/Automattic/jetpack-connection/compare/v1.39.0...v1.39.1
[1.39.0]: https://github.com/Automattic/jetpack-connection/compare/v1.38.0...v1.39.0
[1.38.0]: https://github.com/Automattic/jetpack-connection/compare/v1.37.6...v1.38.0
[1.37.6]: https://github.com/Automattic/jetpack-connection/compare/v1.37.5...v1.37.6
[1.37.5]: https://github.com/Automattic/jetpack-connection/compare/v1.37.4...v1.37.5
[1.37.4]: https://github.com/Automattic/jetpack-connection/compare/v1.37.3...v1.37.4
[1.37.3]: https://github.com/Automattic/jetpack-connection/compare/v1.37.2...v1.37.3
[1.37.2]: https://github.com/Automattic/jetpack-connection/compare/v1.37.1...v1.37.2
[1.37.1]: https://github.com/Automattic/jetpack-connection/compare/v1.37.0...v1.37.1
[1.37.0]: https://github.com/Automattic/jetpack-connection/compare/v1.36.4...v1.37.0
[1.36.4]: https://github.com/Automattic/jetpack-connection/compare/v1.36.3...v1.36.4
[1.36.3]: https://github.com/Automattic/jetpack-connection/compare/v1.36.2...v1.36.3
[1.36.2]: https://github.com/Automattic/jetpack-connection/compare/v1.36.1...v1.36.2
[1.36.1]: https://github.com/Automattic/jetpack-connection/compare/v1.36.0...v1.36.1
[1.36.0]: https://github.com/Automattic/jetpack-connection/compare/v1.35.0...v1.36.0
[1.35.0]: https://github.com/Automattic/jetpack-connection/compare/v1.34.0...v1.35.0
[1.34.0]: https://github.com/Automattic/jetpack-connection/compare/v1.33.0...v1.34.0
[1.33.0]: https://github.com/Automattic/jetpack-connection/compare/v1.32.0...v1.33.0
[1.32.0]: https://github.com/Automattic/jetpack-connection/compare/v1.31.0...v1.32.0
[1.31.0]: https://github.com/Automattic/jetpack-connection/compare/v1.30.13...v1.31.0
[1.30.13]: https://github.com/Automattic/jetpack-connection/compare/v1.30.12...v1.30.13
[1.30.12]: https://github.com/Automattic/jetpack-connection/compare/v1.30.11...v1.30.12
[1.30.11]: https://github.com/Automattic/jetpack-connection/compare/v1.30.10...v1.30.11
[1.30.10]: https://github.com/Automattic/jetpack-connection/compare/v1.30.9...v1.30.10
[1.30.9]: https://github.com/Automattic/jetpack-connection/compare/v1.30.8...v1.30.9
[1.30.8]: https://github.com/Automattic/jetpack-connection/compare/v1.30.7...v1.30.8
[1.30.7]: https://github.com/Automattic/jetpack-connection/compare/v1.30.6...v1.30.7
[1.30.6]: https://github.com/Automattic/jetpack-connection/compare/v1.30.5...v1.30.6
[1.30.5]: https://github.com/Automattic/jetpack-connection/compare/v1.30.4...v1.30.5
[1.30.4]: https://github.com/Automattic/jetpack-connection/compare/v1.30.3...v1.30.4
[1.30.3]: https://github.com/Automattic/jetpack-connection/compare/v1.30.2...v1.30.3
[1.30.2]: https://github.com/Automattic/jetpack-connection/compare/v1.30.1...v1.30.2
[1.30.1]: https://github.com/Automattic/jetpack-connection/compare/v1.30.0...v1.30.1
[1.30.0]: https://github.com/Automattic/jetpack-connection/compare/v1.29.0...v1.30.0
[1.29.0]: https://github.com/Automattic/jetpack-connection/compare/v1.28.0...v1.29.0
[1.28.0]: https://github.com/Automattic/jetpack-connection/compare/v1.27.0...v1.28.0
[1.27.0]: https://github.com/Automattic/jetpack-connection/compare/v1.26.0...v1.27.0
[1.26.0]: https://github.com/Automattic/jetpack-connection/compare/v1.25.2...v1.26.0
[1.25.2]: https://github.com/Automattic/jetpack-connection/compare/v1.25.1...v1.25.2
[1.25.1]: https://github.com/Automattic/jetpack-connection/compare/v1.25.0...v1.25.1
[1.25.0]: https://github.com/Automattic/jetpack-connection/compare/v1.24.0...v1.25.0
[1.24.0]: https://github.com/Automattic/jetpack-connection/compare/v1.23.2...v1.24.0
[1.23.2]: https://github.com/Automattic/jetpack-connection/compare/v1.23.1...v1.23.2
[1.23.1]: https://github.com/Automattic/jetpack-connection/compare/v1.23.0...v1.23.1
[1.23.0]: https://github.com/Automattic/jetpack-connection/compare/v1.22.0...v1.23.0
[1.22.0]: https://github.com/Automattic/jetpack-connection/compare/v1.21.1...v1.22.0
[1.21.1]: https://github.com/Automattic/jetpack-connection/compare/v1.21.0...v1.21.1
[1.21.0]: https://github.com/Automattic/jetpack-connection/compare/v1.20.0...v1.21.0
[1.20.0]: https://github.com/Automattic/jetpack-connection/compare/v1.19.2...v1.20.0
[1.19.2]: https://github.com/Automattic/jetpack-connection/compare/v1.19.1...v1.19.2
[1.19.1]: https://github.com/Automattic/jetpack-connection/compare/v1.19.0...v1.19.1
[1.19.0]: https://github.com/Automattic/jetpack-connection/compare/v1.18.4...v1.19.0
[1.18.4]: https://github.com/Automattic/jetpack-connection/compare/v1.18.3...v1.18.4
[1.18.3]: https://github.com/Automattic/jetpack-connection/compare/v1.18.2...v1.18.3
[1.18.2]: https://github.com/Automattic/jetpack-connection/compare/v1.18.1...v1.18.2
[1.18.1]: https://github.com/Automattic/jetpack-connection/compare/v1.18.0...v1.18.1
[1.18.0]: https://github.com/Automattic/jetpack-connection/compare/v1.17.2...v1.18.0
[1.17.2]: https://github.com/Automattic/jetpack-connection/compare/v1.17.1...v1.17.2
[1.17.1]: https://github.com/Automattic/jetpack-connection/compare/v1.17.0...v1.17.1
[1.17.0]: https://github.com/Automattic/jetpack-connection/compare/v1.15.2...v1.17.0
[1.15.2]: https://github.com/Automattic/jetpack-connection/compare/v1.15.1...v1.15.2
[1.15.1]: https://github.com/Automattic/jetpack-connection/compare/v1.15.0...v1.15.1
[1.15.0]: https://github.com/Automattic/jetpack-connection/compare/v1.14.2...v1.15.0
[1.14.2]: https://github.com/Automattic/jetpack-connection/compare/v1.14.1...v1.14.2
[1.14.1]: https://github.com/Automattic/jetpack-connection/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/Automattic/jetpack-connection/compare/v1.13.1...v1.14.0
[1.13.1]: https://github.com/Automattic/jetpack-connection/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/Automattic/jetpack-connection/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/Automattic/jetpack-connection/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/Automattic/jetpack-connection/compare/1.10.0...v1.11.0
[1.10.0]: https://github.com/Automattic/jetpack-connection/compare/v1.9.0...1.10.0
[1.9.0]: https://github.com/Automattic/jetpack-connection/compare/v1.8.3...v1.9.0
[1.8.3]: https://github.com/Automattic/jetpack-connection/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/Automattic/jetpack-connection/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/Automattic/jetpack-connection/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/Automattic/jetpack-connection/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/Automattic/jetpack-connection/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-connection/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-connection/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/Automattic/jetpack-connection/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-connection/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Automattic/jetpack-connection/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Automattic/jetpack-connection/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/Automattic/jetpack-connection/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Automattic/jetpack-connection/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Automattic/jetpack-connection/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Automattic/jetpack-connection/compare/v1.0.7...v1.1.0
[1.0.7]: https://github.com/Automattic/jetpack-connection/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/Automattic/jetpack-connection/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/Automattic/jetpack-connection/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/Automattic/jetpack-connection/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/Automattic/jetpack-connection/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Automattic/jetpack-connection/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Automattic/jetpack-connection/compare/v1.0.0...v1.0.1
