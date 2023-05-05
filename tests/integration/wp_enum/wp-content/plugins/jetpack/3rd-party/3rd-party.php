<?php
/**
 * Compatibility files for third-party plugins.
 * This is used to improve compatibility of specific Jetpack features with third-party plugins.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack;

use Automattic\Jetpack\Status\Host;

add_action( 'plugins_loaded', __NAMESPACE__ . '\load_3rd_party_compat_filters', 11 );
/**
 * Loads the individual 3rd-party compat functions.
 *
 * This is a refactor of load_3rd_party() to load the individual compat files only when needed instead of universally.
 */
function load_3rd_party_compat_filters() {
	// SalesForce
	// @todo This one probably makes more sense to move to the Forms package (and the module until it is fully deprecated).
	require_once JETPACK__PLUGIN_DIR . '/3rd-party/class-salesforce-lead-form.php'; // not a module but the handler for Salesforce forms

	// bbPress
	if ( function_exists( 'bbpress' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/bbpress.php';
	}

	// Beaver Builder
	if ( class_exists( 'FLBuilder' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/beaverbuilder.php';
	}

	// Bitly
	if ( class_exists( 'Bitly' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/bitly.php';
	}

	// BuddyPress
	if ( class_exists( 'BuddyPress' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/buddypress.php';
	}

	// AMP. AMP__DIR__ is defined in the AMP plugin since the very first version.
	if ( Constants::is_defined( 'AMP__DIR__' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/amp.php';
	}

	// Domain Mapping. All assume multisite, so it's an easy check.
	if ( Constants::is_defined( 'SUNRISE' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/class-domain-mapping.php';
	}

	// Debug Bar
	if ( class_exists( 'Debug_Bar' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/debug-bar.php';
	}

	// Letting these always load since it handles somethings upon plugin activation.
	require_once JETPACK__PLUGIN_DIR . '/3rd-party/creative-mail.php';
	require_once JETPACK__PLUGIN_DIR . '/3rd-party/jetpack-backup.php';
	require_once JETPACK__PLUGIN_DIR . '/3rd-party/jetpack-boost.php';
	require_once JETPACK__PLUGIN_DIR . '/3rd-party/woocommerce-services.php';

	// Crowdsignal. @todo Review the usage of modern Jetpack with outdated Crowdsignal.
	require_once JETPACK__PLUGIN_DIR . '/3rd-party/crowdsignal.php';

	// qTranslate. Plugin closed in 2021, but leaving support for now to allow sites to drop it.
	if ( Constants::is_defined( 'QTX_VERSION' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/qtranslate-x.php';
	}

	// VaultPress.
	if ( Constants::is_defined( 'VAULTPRESS__VERSION' ) || class_exists( 'VaultPress' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/vaultpress.php';
	}

	// Web Stories
	if ( Constants::is_defined( 'WEBSTORIES_VERSION' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/web-stories.php';
	}

	// WooCommerce
	if ( class_exists( 'WooCommerce' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/woocommerce.php';
	}

	// Atomic Weekly
	if ( ( new Host() )->is_atomic_platform() ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/atomic.php';
	}

	// WPML
	if ( defined( 'ICL_SITEPRESS_VERSION' ) ) {
		require_once JETPACK__PLUGIN_DIR . '/3rd-party/wpml.php';
	}
}
