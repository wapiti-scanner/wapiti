<?php
/**
 * Module Name: Site verification
 * Module Description: Establish your site's authenticity with external services.
 * First Introduced: 3.0
 * Sort Order: 33
 * Requires Connection: No
 * Auto Activate: Yes
 * Feature: Engagement
 * Additional Search Queries: webmaster, seo, google, bing, pinterest, search, console
 *
 * @package automattic/jetpack
 */

/**
 * Load Verification Tools code.
 */
function jetpack_load_verification_tools() {
	include __DIR__ . '/verification-tools/blog-verification-tools.php';
}

/**
 * Functionality to load for Verification Tools after all modules have been loaded.
 */
function jetpack_verification_tools_loaded() {
	Jetpack::enable_module_configurable( __FILE__ );
}
add_action( 'jetpack_modules_loaded', 'jetpack_verification_tools_loaded' );

jetpack_load_verification_tools();
