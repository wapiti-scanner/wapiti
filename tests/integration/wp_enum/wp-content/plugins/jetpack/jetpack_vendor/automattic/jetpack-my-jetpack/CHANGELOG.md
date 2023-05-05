# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.11.0] - 2023-05-01
### Added
- Added Jetpack Starter bundle post-activation screen and plan header [#30368]

## [2.10.3] - 2023-04-25
### Added
- My Jetpack: Add flags field in initial state [#30241]
- My Jetpack: Add Install/Activate menu actions based on the standalone plugin status. [#30153]
- My Jetpack: Add neutral color in contextual card [#30250]
- My Jetpack: Add side-effect action to request the standalone plugin installation on the backend. [#30143]
- My Jetpack: Add stats to VideoPress card [#30197]
- My Jetpack: Enable menu for all hybrid products [#30247]
- My Jetpack: Reload page after standalone action [#30221]

### Changed
- My Jetpack: Connect the standalone plugin menu options so they trigger the installation and activation when clicked. [#30168]
- MyJetpack: set the Social standalone page as the default admin one [#30193]
- MyJetpack: Try to activate the product module after installing the standalone plugin [#30215]
- Updated package dependencies. [#30015]

## [2.10.2] - 2023-04-17
### Added
- Ad missing TOS in Jetpack interstitial. [#29683]
- My Jetpack: Add endpoint to install the standalone plugin for hybrid products. [#30045]
- My Jetpack: Expose information about standalone plugin status on My Jetpack product initial state. [#29977]

### Changed
- Backup and Scan: redirect after checkout to Jetpack recommendations page if Jetpack plugin is active. Otherwise, redirect back to plugin admin page. [#29708]
- My Jetpack: Adjustments in Product Card [#30014]
- Updated package dependencies. [#30019]

## [2.10.1] - 2023-04-10
### Added
- Add Jetpack Autoloader package suggestion. [#29988]
- My Jetpack: Introduce absent_with_plan status [#29920]

### Changed
- My Jetpack: Turn Search into a hybrid product to handle it as module and as standalone plugin. [#29946]
- My Jetpack: Turn Social into a hybrid product to handle it as module and as standalone plugin. [#29935]
- My Jetpack: Turn VaultPress Backup into a Hybrid product to handle it as module and as standalone plugin. [#29928]
- My Jetpack: Turn VideoPress into a Hybrid product to handle it as module and as standalone plugin. [#29918]

## [2.10.0] - 2023-04-04
### Added
- My Jetpack: Adds a selector, reducer and resolver machinery to fetch product stats. [#29764]
- My Jetpack: Enhance Product Card [#29787]
- My Jetpack: Introduce menu in Product Card [#29815]

### Changed
- * Updated add-anti-spam path to add-akismet to match the product key
  * Updated product interstitial component to accept an existingLicenseKeyUrl
  * Updated product interstitial component to display a product name instead of a title where preferProductName is set
  * Make is_plugin_active available from the API [#29598]
- My Jetpack: Change the bottom of My Jetpack screen to use single-column rows on small viewports. [#29844]
- Updated package dependencies. [#29854]

## [2.9.2] - 2023-04-03
### Changed
- Internal updates.

## [2.9.1] - 2023-03-28
### Changed
- Move GoldenTokenModal component to licensing package. [#29748]

## [2.9.0] - 2023-03-27
### Added
- Adds new route for Golden Token. Also the experience of redeeming one [#29644]
- Clarified when license activation fails that a user connection is required, added a link to complete the connection, and added functionality to redirect back to license activation when the connection is done. [#29443]

## [2.8.1] - 2023-03-20
### Changed
- Product Interstitial: Use browser history to go back, in case they're coming from somewhere outside of the app. [#29138]
- Updated My Jetpack wpwrap color to --jp-white-off [#29568]
- Updated package dependencies. [#29471]

## [2.8.0] - 2023-03-13
### Added
- Add Zendesk chat module to My Jetpack page [#28712]

## [2.7.13] - 2023-03-08
### Changed
- Updated package dependencies. [#29216]

## [2.7.12] - 2023-02-28
### Changed
- Update billing language [#29126]

## [2.7.11] - 2023-02-20
### Fixed
- My Jetpack: Fix button to add bundle in product interstitial component [#28984]

## [2.7.10] - 2023-02-15
### Changed
- Update to React 18. [#28710]

## [2.7.9] - 2023-02-08
### Changed
- Updated package dependencies. [#28682, #28700]

## [2.7.8] - 2023-02-06
### Changed
- Updated package dependencies.

## [2.7.7] - 2023-01-26
### Changed
- Use `flex-start` instead of `start` for better browser compatibility. [#28530]

## [2.7.6] - 2023-01-25
### Changed
- Minor internal updates.

## [2.7.5] - 2023-01-23
### Fixed
- Components: Fix usage of box-sizing across the elements [#28489]
- Fixes the price display for products with intro offers for the first month. [#28424]

## [2.7.4] - 2023-01-16
### Changed
- Updated package dependencies. [#28303]

## [2.7.3] - 2023-01-11
### Changed
- Updated package dependencies.

## [2.7.2] - 2023-01-02
### Added
- My Jetpack: Move VideoPress from Hybrid [#28097]

### Changed
- My Jetpack: Move Search out of hybrid and deprecate Hybrid_Product class [#28113]

## [2.7.1] - 2022-12-27
### Changed
- Fix layout visual issues [#28055]
- My Jetpack: Move Backup out of hybrid product [#28022]
- My Jetpack: Move Social out of hybrid product [#28074]

## [2.7.0] - 2022-12-19
### Added
- Implement detached licenses redux store. [#27609]

### Changed
- Updated package dependencies. [#27916]

### Fixed
- Add translation context to Security product name. [#27920]

## [2.6.1] - 2022-12-12
### Changed
- Updated package dependencies. [#27888]

## [2.6.0] - 2022-12-05
### Changed
- Improve design of the error notice. [#27340]
- Updated package dependencies. [#27340]

## [2.5.2] - 2022-12-02
### Changed
- My Jetpack: Requires connection only if needed [#27615]
- Updated package dependencies. [#27697]

## [2.5.1] - 2022-11-30

## [2.5.0] - 2022-11-28
### Changed
- My Jetpack: rename Backup and Anti-Spam to new product names [#27377]
- Show My Jetpack even if site is disconnected [#26967]
- Updated package dependencies. [#27576]

## [2.4.1] - 2022-11-22
### Changed
- Updated package dependencies. [#27043]

## [2.4.0] - 2022-11-17
### Added
- Added Jetpack Protect to My Jetpack. [#26069]

### Changed
- Updated package dependencies. [#26736]

## [2.3.5] - 2022-11-10
### Changed
- Updated package dependencies. [#27319]

## [2.3.4] - 2022-11-08
### Changed
- Updated package dependencies. [#27289]

## [2.3.3] - 2022-11-01
### Changed
- Updated package dependencies. [#27196]

## [2.3.2] - 2022-10-25
### Changed
- Updated package dependencies. [#26705]

## [2.3.1] - 2022-10-25
### Added
- Add a flag to indicate if the pricing is introductory with product price [#26982]
- My Jetpack: Support trial [#27033]

### Changed
- Search: now support 38 languages [#27025]

### Fixed
- Don't show old price when it's the same as new one [#27015]
- Search: check if free plan and new pricing is active using wpcom API [#27016]

## [2.3.0] - 2022-10-19
### Added
- Added support for free product and added free product for Search [#26808]

### Changed
- Updated package dependencies. [#26883]

## [2.2.3] - 2022-10-17
### Changed
- Updated package dependencies. [#26851]

## [2.2.2] - 2022-10-13
### Changed
- Updated package dependencies. [#26790]

## [2.2.1] - 2022-10-11
### Changed
- Updated package dependencies. [#25973]

## [2.2.0] - 2022-10-05
### Added
- Integrate the new connection error message React component into My Jetpack. [#26485]
- Search: add post type breakdown endpoint [#26463]
- Trigger restore connection flow. [#26489]

### Changed
- Updated package dependencies. [#26457]

## [2.1.1] - 2022-09-27
### Changed
- Updated package dependencies.

## [2.1.0] - 2022-09-20
### Added
- Added the ConnectionErrorNotice React component. [#26259]

### Changed
- Updated package dependencies.

### Fixed
- Fixed the tests for the Module_Product class by creating and using a sample, test-only module product class as the test subject instead of relying on Videopress or other concrete products. [#26227]

## [2.0.5] - 2022-09-08
### Changed
- Change VideoPress into a Hybrid product in My Jetpack [#25954]
- Updated package dependencies.

## [2.0.4] - 2022-08-31
### Added
- Allow plugins to override a product class. [#25891]

### Changed
- Updated package dependencies. [#25856]

## [2.0.3] - 2022-08-29
### Changed
- Updated package dependencies.

## [2.0.2] - 2022-08-25
### Changed
- Activate plugins in normal mode to trigger plugin_activated hooks [#25727]
- Updated package dependencies. [#25814]

### Fixed
- Licensing: do not enable the Licensing UI if My Jetpack cannot be enabled. [#25667]
- Search: increased search plan/pricing API timeouts to 5s [#25775]

## [2.0.1] - 2022-08-23
### Added
- My Jetpack: Add container for JITMs [#22452]

### Changed
- Updated package dependencies. [#25338, #25339, #25377, #25422, #25628, #25762, #25764]

## [2.0.0] - 2022-08-09
### Added
- Make product cards compatible with disclaimers and add disclaimer for backup card [#25265]

### Changed
- Search: changed to only require site level connection [#24477]

## [1.8.3] - 2022-08-03
### Changed
- Updated package dependencies. [#25300, #25315]

## [1.8.2] - 2022-07-27
### Changed
- My Jetpack: changed link used in ProductCard component to a button when the plugin is absent

## [1.8.1] - 2022-07-26
### Changed
- My Jetpack: changed button used in ProductCard component from WordPress to Jetpack default [#25146]
- Updated package dependencies. [#25147]

## [1.8.0] - 2022-07-19
### Added
- My Jetpack: scroll window to top on route change [#25086]

### Changed
- Updated package dependencies. [#24710]

## [1.7.4] - 2022-07-12
### Changed
- Updated package dependencies. [#25048, #25055]

## [1.7.3] - 2022-07-06
### Added
- Display alert when we cant automatically install the plugin [#24884]

### Changed
- Updated package dependencies. [#24923]

## [1.7.2] - 2022-06-28
### Changed
- Disambiguate redirectUrls vars [#24839]
- Search: use centralized search pricing API [#24795]
- Updated package dependencies. [#24826]

### Fixed
- Search Pricing: fix pricing fetch issue before site is connected [#24826]

## [1.7.1] - 2022-06-21
### Fixed
- My Jetpack: Replace wordpress from PNG to SVG at Connection [#24793]

## [1.7.0] - 2022-06-21
### Changed
- My Jetpack: set products grid to 3x3 for large viewport size
- Renaming master to trunk.
- Renaming `master` references to `trunk`

## [1.6.2] - 2022-06-14
### Changed
- Updated package dependencies. [#24529]

## [1.6.1] - 2022-06-08
### Changed
- Reorder JS imports for `import/order` eslint rule. [#24601]
- Updated package dependencies. [#24510]

## [1.6.0] - 2022-05-30
### Added
- Added Social to My Jetpack.

### Changed
- Make My Jetpack use the new Modules class
- Replace deprecated external-link variation by using isExternalLink prop
- Updated package dependencies

## [1.5.0] - 2022-05-24
### Changed
- Default licensing UI in My Jetpack to be enabled [#24396]
- Updated package dependencies. [#24449]

## [1.4.1] - 2022-05-19
### Changed
- Updated package dependencies. [#24395]

## [1.4.0] - 2022-05-18
### Added
- Added a filter to allow stand-alone plugins to add product specific activation routines [#24334]
- My Jetpack: Add Protect class [#24347]
- My Jetpack: compute Search plugin price based on price tier [#24337]

### Changed
- Add tiered pricing copy and update titles for Jetpack Search [#24357]
- Hide Activate a license link if there is no user connection since user connection is required [#24251]
- My Jetpack Hybrid products: Install Jetpack if stand-alone plugin installation fails [#24335]
- Updated Jetpack Scan feature list. [#23863] [#23795] [#24361] [#24372]

## [1.3.0] - 2022-05-10
### Changed
- Adds from arg to connection screen in My Jetpack so that we can begin tracking connections originating from My Jetpack [#24283]
- Updated package dependencies. [#24189]
- Updated references to old licensing activation UI to licensing activation UI in My Jetpack [#24189]

## [1.2.1] - 2022-05-04
### Added
- Add missing JavaScript dependencies. [#24096]

### Changed
- My Jetpack: remove duplicated site suffix stored on rawUrl. Use siteSuffix instead. [#24094]
- Updated package dependencies. [#24095] [#24198]

### Deprecated
- Moved the options class into Connection. [#24095]

## [1.2.0] - 2022-04-26
### Added
- Added activation screen component to My Jetpack licensing page

### Changed
- Updated package dependencies.
- Update package.json metadata.

## [1.1.0] - 2022-04-19
### Added
- Adds a skeleton for the licensing UI along with a feature flag
- Better error handling for when the WPCOM server is unreachable
- Introduced ConnectedProductOffer component

### Changed
- Turn Search into a Hybrid Product
- Updated package dependencies
- use connected plugin list from the connection store and ask for an update after activating a product

## [1.0.2] - 2022-04-12
### Changed
- Updated package dependencies.

### Fixed
- Fixed bug in checkout URLs for sites installed in subdirs.

## [1.0.1] - 2022-04-06
### Removed
- Removed tracking dependency.

## [1.0.0] - 2022-04-05
### Added
- My Jetpack: improve Product and Interstitial components.

### Changed
- Bump My Jetpack package to major version 1.0.0.
- My Jetpack: align price boxes in the interstitial product page.
- Updated package dependencies.

## [0.6.13] - 2022-03-31
### Added
- Added tracking events to Plans section external links

### Changed
- My Jetpack: tweak plans section typography and descriptive text

## [0.6.12] - 2022-03-29
### Added
- Add missing JS peer dependencies.

### Changed
- Microperformance: Use === null instead of is_null
- My Jetpack: Moved in product icon components
- My Jetpack: Tweak plan sections styles/sizes
- My Jetpack: Update ProductDetailCard to use components and theme variables
- My Jetpack: Use components to render headers elements
- Use different URLs for manage and purchase links in plans section

### Fixed
- My Jetpack: Connect Screen logos quality

## [0.6.11] - 2022-03-23
### Added
- My Jetpack: add error styles to the whole Product card component
- My Jetpack: Make whole Product card clickable

### Changed
- Changed opacity of product icons to 40%
- Changed title
- Improved should_initialize method
- My Jetpack: remove dropdown from CTA button in Product cards
- My Jetpack: Use Text and CSS vars on ProductCard
- Updated Boost product icon for clarity
- Updated package dependencies.
- Updated package dependencies.
- Updated styles for each product card status
- Update organization and copy of the Plans section

### Removed
- My Jetpack: Remove client code that allows to deactivate a product

### Fixed
- Fix Plans section top margin for plan list
- My Jetpack: jetpack_my_jetpack_should_initialize filter now respected when set to true.

## [0.6.10] - 2022-03-15
### Changed
- Make Backup go through the purchase flow after activation
- My Jetpack: Use ThemeProvider instead base-styles
- Updated package dependencies

### Removed
- Removed Beta badge from menu item

## [0.6.9] - 2022-03-09
### Changed
- Updated package dependencies.

## [0.6.8] - 2022-03-08
### Added
- Added connected plugins slugs to My Jetpack tracking events
- Add link to jetpack.com in the footer
- My Jetpack: Add jetpack features link on connection screen
- My Jetpack: tidy Product card component
- My Jetpack: update Spinner in checkout button

### Changed
- Components: update attributes used within the Button component to match recent deprecations and changes.
- My Jetpack: Add Connected Product Card stories
- My Jetpack: Add connection screen footer
- My Jetpack: clean/tidy Product data
- My Jetpack: Remove Layout component
- Only consider Backup product active when the plan is purchased

### Fixed
- Fixed Backup flow when Jetpack plugin is active
- My Jetpack: align CTA buttons of My Jetpack overview
- My Jetpack: Fix button height in the Interstitial pages

## [0.6.7] - 2022-03-02
### Added
- Add My Jetpack action link to all Jetpack plugins
- My Jetpack: Handle cosmetic tweaks
- My Jetpack: Pass requiresUserConnection to ConnectionStatusCard

### Changed
- Refactor and simplify Products class
- Updated package dependencies.

### Fixed
- Disable browser cache for My Jetpack
- My Jetpack: fix products card section story
- My Jetpack: fix stories for the Interstitial pages

## [0.6.6] - 2022-02-28
### Fixed
- Re-doing 0.6.5 to fixup bad release.

## [0.6.5] - 2022-02-28
### Changed
- Tweak product card box model.

### Fixed
- Use namespace in My Jetpack REST Products class to prevent fatal

## [0.6.4] - 2022-02-25
### Added
- Activate Jetpack plugin from Extras product card
- Added list of connected plugins to Disconnect dialog in My Jetpack
- Add Extras interstitial page
- My Jetpack: Handle cosmetic tweaks
- My Jetpack: Remove global notices when in my jetpack page
- My Jetpack: set height of Jetpack logo in the footer
- My Jetpack: tweak height of Jetpack Logo
- My Jetpack: update Product logos

### Changed
- Disable My Jetpack on MS
- My Jetpack: compress extras product image
- Updated package dependencies.
- Update My Jetpack dashboard headline

### Removed
- Remove unnecessary line from My Jetpack Initial state

### Fixed
- Fix beta badge for RTL languages
- Handle plugin activating from Hybrid class
- Memoized RecordEvent from usAnalytics hook
- My Jetpack: Fix post activation url redirect
- My Jetpack: Move product list that requires user connection to selector
- Products::get_products_names should not load all product information
- Update automattic logo href in the footer

## [0.6.3] - 2022-02-22
### Changed
- Updated inline documentation

### Fixed
- Use Jetpack namespace to fix fatal error

## [0.6.2] - 2022-02-22
### Added
- Add Beta badge
- Add Extras class
- Apply coupon discount to Product price when it exists
- Filesystem write access to the initial state
- Improve Product detail layout
- Implement close link on layout nav
- Prevent calling activation hook when activating backup

### Changed
- Bump package versions.
- Improve My Jetpack link styles
- Improve redirect process after installing Product
- Fix interstitial CTA buttons layout
- Move from isPressed to CSS vars
- Redirect connect user to connection interstitial
- Point the link of the Manage button of CRM to its dashboard
- Redirect to post_activation_url after product activation from iterstitial screen
- Remove conditional loading depending on constant
- Send My Jetpack version with fired events
- Update the layout of interstitial page when it has an upgradable bundle

### Fixed
- Check if product is active before checking if requires plan
- Fix check for plugin installation for hybrid products
- Fix click on security and add click on My Jetpack interstitial
- Fix clicks on VideoPress and CRM cards
- Fix Product prices
- Make Scan and Search interstitials install the plugin
- Purchases: ensure we retrieve translated version of active purchases
- Return needs purchase status for products module

## [0.6.1] - 2022-02-16
### Added
- Add Anti-Spam Product detail card
- Add CRM interstitial page
- Added wpcom plan slug to product info
- add manage and post activation urls
- Add Scan product: interstitial, route, data, etc...
- Add Security Product Bundle
- Add VideoPress data
- Add VideoPress interstitial cmp. Story.
- Add `#/add-videopress` route
- Change the discount value for all Products to 50
- checks and activation for Security Bundle
- consume prices dynamically
- Do not show Porduct price when plan has required plan
- Finish Backup, Anti-Spam and Scan interstitial pages
- Fire Tracks Event when user clicks on Product Interstitial Back link
- Install proudcts from interstitial pages
- Make click on Fix connection show connection route
- package version to main class
- Pull product discount from wpcom
- Refactoring -> add icons component -> tweak icons for interstitial pages
- Register `#/add-anti-spam` route. Connect with interstitial page
- Restore Security bundle card in the UI
- Set default values for product data in the client (custom hook)
- set product status as error if active and requiring a missing user connection
- Set properly the checkout link for Products
- Set unlink=1 in the checkout URL when the user is not connected
- Tidy Product stories
- Update Backup product data. Tweak Icon.
- Update mock data for Search product. useMyJetpackNavigate() hook

### Changed
- Adapt Scan actiavtion behavior as it is not a module
- Add global notices for activate/deactivate failures
- Add manage redirect
- Apply correct style for CTA buttons on Interstitial
- Avoid usage of 100vh on layout
- Fix setting height of the Product title in the detail component
- Implement is fulfilled handler for product resolver
- Improve global notice layout
- Reduce size of boost and search interstitial images
- Update structure with Layout component
- Only pass a productUrl if the product is not free on interstitial pages
- Only show the deactivate action when it makes sense
- Pass slug prop to event firing on product card button actions instead of name
- Remove unnecessary payload from  request to activate or deactivate a product
- Replace renderActionButton function for ActionButton component
- Updated package dependencies.
- Use useMyJetpackNavigate when it's worth it

### Fixed
- Fixed connection check labels and error message
- Fix upgradability for anti-spam and backup products
- Remove duplicted Icon in Product Card story
- Use key when looping through product detail icons

## [0.6.0] - 2022-02-09
### Added
- Add Boost interstitial cmp.
- Add has_required_plan to product info and implement method in Search
- Add Product princign harcoded data
- Add search product data
- Add title and features to products data
- anti spam product class
- Connect Boost card with the interstitial page via /add-boost root
- Fire Tracks event when clicking CTA button on product Interstitial page
- Fire Tracks event when clicking Manage button on product card
- Fire Tracks event when clickn Add link on My Jetpack product card
- Fire Tracks event when showing the Interstitial page
- Implement Free price for Boost product
- Implement Search product interstitial
- Introduce basic Layout component. Add GoBackLink component
- Introduce ProductDetailCard component
- My Jetpack: Add Connection screen
- Pass slug prop to ProductCard'
- Plan verification for Backup and Scan
- Restore getProduct() resolver
- Set the checkout URL for the Product detail component
- useCallback for functions that are bound to onEvents

### Changed
- My Jetpack: Implement handler of connection notices
- My Jetpack: Update notice style and implements redirect for connection route
- Support multiple possible folder for each plugin
- Updated package dependencies

### Removed
- dependency from search package

### Fixed
- Fix My Jetpack's reducer for SET_PRODUCT_STATUS
- Fix the redirect URL value
- Show discounted price in Product Detail card
- typo

## [0.5.0] - 2022-02-02
### Added
- Added plugin installation functionality
- Adds Tracks events for activating and deactivating products from the product cards
- Fixes stories for ProductCard component
- Handle when site is not connected
- Initial approach to handle global notice
- Module Products
- My Jetpack: Add route handling
- My Jetpack: connect all product cards with data provider
- My Jetpack: connect Backup product class with Product class. Add long description and features fields.
- My Jetpack: handle redirect when no connection #22549
- My Jetpack: reorganize stores by project/name
- Remove getProduct() resolver
- Support to Hybrid products
- Tweak dimms of the Product card status
- Update data handling - Implement request status in Product Card
- User connection requirement to product info
- uses the Plugin Installer package to safely checks plugins statuses

### Changed
- Added filter for disabling the initialization of the My Jetpack package
- Build: remove unneeded files from production build.
- Do not initialize My Jetpack id site is not connected
- My Jetpack: Refactor styles to use layout components and theme provider
- My Jetpack: Update gap between product cards section
- Pick API root and nonce values from a new window var myJetpackRest
- Updated package dependencies.
- Update plugin absent status consistently

### Fixed
- added unit test mock for new global variable myJetpackRest
- Fix tests
- Fix unsafe optional chaining.
- my-jetpack: fix tracking event when activating product
- Resolved minor code standard violation after implementing a stricter rule.

## [0.4.0] - 2022-01-25
### Added
- add API endpoints to manipulate products
- Added css module for My Jetpack Plans Section
- Added useAnalytics hook
- Added Visitor class for status regarding the site visitor.
- Add first data approach
- Add Products and REST_Products basic classes
- Adds very basic product cards section component to my jetpack
- My Jetpack: Add Product Card component
- My Jetpack: check user connectivity before to hit wpcom side
- My Jetpack: Implement data handling for enable/disable products
- Removed endpoint plans superseded by purchases

### Changed
- Add Connections Section wrapping the Connection Status Card to My Jetpack
- Build: do not ship raw files in production bundle.

### Removed
- Remove unused usePlans() custom react hook

### Fixed
- Fixed svg attribute strokeWidth for Boost Card

## [0.3.3] - 2022-01-18
### Added
- Added redux store specific to my-jetpack
- Implement plans list properly in the PlansSection
- My Jetpack: Add scripts for JS tests
- My Jetpack: Include wordpress components as dep
- Reduxify purchases data

### Changed
- General: update required node version to v16.13.2
- Properly style the Plans Section according to proposed design
- Updated package dependencies.

## [0.3.2] - 2022-01-13
### Added
- My Jetpack: add story to `<PlanSection />` component
- My Jetpack: first PlanSection implementation

### Fixed
- Rename method enqueue_scritps to enqueue_scripts

## [0.3.1] - 2022-01-11
### Added
- Add devvelopment testing instructions to doc.

### Changed
- Updated package dependencies.

### Removed
- Remove use of deprecated `~` in sass-loader imports.

## [0.3.0] - 2022-01-04
### Changed
- Drop isRegistered and isUserConnected params from ConnectionStatusCard component
- Switch to pcov for code coverage.
- Updated package dependencies.
- Updated package textdomain from `jetpack` to `jetpack-my-jetpack`.

## [0.2.0] - 2021-12-14
### Added
- Added Connection Status Card to the page.
- Janitorial: add watch command to the plugin.

### Changed
- Adapt to new layout components.
- Build: do not ship scss and jsx files in production build.

### Fixed
- Build minimized JS for the production build.
- Fix JavaScript i18n strings.

## [0.1.3] - 2021-12-07
### Changed
- Updated package dependencies.

## [0.1.2] - 2021-11-30
### Added
- Janitorial: create mirror repo for the package.

### Changed
- Remove now-redundant `output.filename` from Webpack config.

## 0.1.1 - 2021-11-23
### Changed
- Updated package dependencies.

## 0.1.0 - 2021-11-17
### Added
- Created package

[2.11.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.10.3...2.11.0
[2.10.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.10.2...2.10.3
[2.10.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.10.1...2.10.2
[2.10.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.10.0...2.10.1
[2.10.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.9.2...2.10.0
[2.9.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.9.1...2.9.2
[2.9.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.9.0...2.9.1
[2.9.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.8.1...2.9.0
[2.8.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.8.0...2.8.1
[2.8.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.13...2.8.0
[2.7.13]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.12...2.7.13
[2.7.12]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.11...2.7.12
[2.7.11]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.10...2.7.11
[2.7.10]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.9...2.7.10
[2.7.9]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.8...2.7.9
[2.7.8]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.7...2.7.8
[2.7.7]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.6...2.7.7
[2.7.6]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.5...2.7.6
[2.7.5]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.4...2.7.5
[2.7.4]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.3...2.7.4
[2.7.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.2...2.7.3
[2.7.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.1...2.7.2
[2.7.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.7.0...2.7.1
[2.7.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.6.1...2.7.0
[2.6.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.6.0...2.6.1
[2.6.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.5.2...2.6.0
[2.5.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.5.1...2.5.2
[2.5.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.5.0...2.5.1
[2.5.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.4.1...2.5.0
[2.4.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.4.0...2.4.1
[2.4.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.3.5...2.4.0
[2.3.5]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.3.4...2.3.5
[2.3.4]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.3.3...2.3.4
[2.3.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.3.2...2.3.3
[2.3.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.3.1...2.3.2
[2.3.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.3.0...2.3.1
[2.3.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.2.3...2.3.0
[2.2.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.2.2...2.2.3
[2.2.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.2.1...2.2.2
[2.2.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.2.0...2.2.1
[2.2.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.1.1...2.2.0
[2.1.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.1.0...2.1.1
[2.1.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.0.5...2.1.0
[2.0.5]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.0.4...2.0.5
[2.0.4]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.0.3...2.0.4
[2.0.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.0.2...2.0.3
[2.0.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.0.1...2.0.2
[2.0.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.8.3...2.0.0
[1.8.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.8.2...1.8.3
[1.8.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.8.1...1.8.2
[1.8.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.8.0...1.8.1
[1.8.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.7.4...1.8.0
[1.7.4]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.7.3...1.7.4
[1.7.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.7.2...1.7.3
[1.7.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.7.1...1.7.2
[1.7.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.7.0...1.7.1
[1.7.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.6.2...1.7.0
[1.6.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.6.1...1.6.2
[1.6.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.6.0...1.6.1
[1.6.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.5.0...1.6.0
[1.5.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.4.1...1.5.0
[1.4.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.4.0...1.4.1
[1.4.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.2.1...1.3.0
[1.2.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.2.0...1.2.1
[1.2.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.0.2...1.1.0
[1.0.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.0.1...1.0.2
[1.0.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.13...1.0.0
[0.6.13]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.12...0.6.13
[0.6.12]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.11...0.6.12
[0.6.11]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.10...0.6.11
[0.6.10]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.9...0.6.10
[0.6.9]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.8...0.6.9
[0.6.8]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.7...0.6.8
[0.6.7]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.6...0.6.7
[0.6.6]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.5...0.6.6
[0.6.5]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.4...0.6.5
[0.6.4]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.3...0.6.4
[0.6.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.2...0.6.3
[0.6.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.1...0.6.2
[0.6.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.3.3...0.4.0
[0.3.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.3.2...0.3.3
[0.3.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.3.1...0.3.2
[0.3.1]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.1.3...0.2.0
[0.1.3]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/Automattic/jetpack-my-jetpack/compare/0.1.1...0.1.2
