<?php
/**
 * Load all Jetpack files that do not get loaded via the autoloader.
 *
 * @package automattic/jetpack
 */

/**
 * Checks if the code debug mode turned on, and returns false if it is. When Jetpack is in
 * code debug mode, it shouldn't use minified assets. Note that this filter is not being used
 * in every place where assets are enqueued. The filter is added at priority 9 to be overridden
 * by any default priority filter that runs after it.
 *
 * @since 6.2.0
 *
 * @return boolean
 *
 * @filter jetpack_should_use_minified_assets
 */
function jetpack_should_use_minified_assets() {
	return ! defined( 'SCRIPT_DEBUG' ) || ! SCRIPT_DEBUG;
}
add_filter( 'jetpack_should_use_minified_assets', 'jetpack_should_use_minified_assets', 9 );

// @todo: Abstract out the admin functions, and only include them if is_admin()
require_once JETPACK__PLUGIN_DIR . 'class.jetpack.php';
require_once JETPACK__PLUGIN_DIR . 'class.jetpack-network.php';
require_once JETPACK__PLUGIN_DIR . 'class.jetpack-client-server.php';
require_once JETPACK__PLUGIN_DIR . 'class.jetpack-user-agent.php';
require_once JETPACK__PLUGIN_DIR . 'class.jetpack-post-images.php';
require_once JETPACK__PLUGIN_DIR . 'class.jetpack-heartbeat.php';
require_once JETPACK__PLUGIN_DIR . 'class.photon.php';
require_once JETPACK__PLUGIN_DIR . 'functions.photon.php';
require_once JETPACK__PLUGIN_DIR . 'functions.global.php';
require_once JETPACK__PLUGIN_DIR . 'functions.compat.php';
require_once JETPACK__PLUGIN_DIR . 'class-jetpack-gallery-settings.php';
require_once JETPACK__PLUGIN_DIR . 'functions.cookies.php';
require_once JETPACK__PLUGIN_DIR . 'class.jetpack-autoupdate.php';
require_once JETPACK__PLUGIN_DIR . 'class.frame-nonce-preview.php';
require_once JETPACK__PLUGIN_DIR . 'modules/module-headings.php';
require_once JETPACK__PLUGIN_DIR . 'class.jetpack-connection-banner.php';
require_once JETPACK__PLUGIN_DIR . 'class-jetpack-connection-widget.php';
require_once JETPACK__PLUGIN_DIR . 'class.jetpack-plan.php';
// Used by the API endpoints.
require_once JETPACK__PLUGIN_DIR . 'modules/seo-tools/class-jetpack-seo-utils.php';
require_once JETPACK__PLUGIN_DIR . 'modules/seo-tools/class-jetpack-seo-titles.php';
require_once JETPACK__PLUGIN_DIR . 'modules/seo-tools/class-jetpack-seo-posts.php';
require_once JETPACK__PLUGIN_DIR . 'modules/verification-tools/verification-tools-utils.php';

require_once JETPACK__PLUGIN_DIR . 'class-jetpack-xmlrpc-methods.php';
Jetpack_XMLRPC_Methods::init();

require_once JETPACK__PLUGIN_DIR . 'class-jetpack-connection-status.php';
Jetpack_Connection_Status::init();

require_once JETPACK__PLUGIN_DIR . '_inc/lib/class-jetpack-recommendations.php';
require_once JETPACK__PLUGIN_DIR . 'class-jetpack-recommendations-banner.php';

if ( is_admin() ) {
	require_once JETPACK__PLUGIN_DIR . 'class.jetpack-admin.php';
	require_once JETPACK__PLUGIN_DIR . '_inc/lib/debugger.php';
}

// Play nice with https://wp-cli.org/.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once JETPACK__PLUGIN_DIR . 'class.jetpack-cli.php';
}

require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.core-rest-api-endpoints.php';
require_once JETPACK__PLUGIN_DIR . '_inc/blogging-prompts.php';

add_action( 'updating_jetpack_version', array( 'Jetpack', 'do_version_bump' ), 10, 2 );
add_filter( 'is_jetpack_site', '__return_true' );

require_once JETPACK__PLUGIN_DIR . '3rd-party/3rd-party.php';

Jetpack::init();
