<?php
/**
 * Theme Tools: Site Logo.
 *
 * @see https://jetpack.com/support/site-logo/
 *
 * This feature will only be activated for themes that declare their support.
 * This can be done by adding code similar to the following during the
 * 'after_setup_theme' action:
 *
 * $args = array(
 *  'header-text' => array(
 *      'site-title',
 *      'site-description',
 *  ),
 *  'size' => 'medium',
 * );
 * add_theme_support( 'site-logo', $args );
 *
 * @package automattic/jetpack
 */

/**
 * Activate the Site Logo plugin.
 *
 * @uses current_theme_supports()
 * @since 3.2.0
 * @since 9.9.0 Uses Core site_logo option format universally.
 */
function site_logo_init() {
	// Only load our code if our theme declares support, and the standalone plugin is not activated.
	if ( current_theme_supports( 'site-logo' ) && ! class_exists( 'Site_Logo', false ) ) {
		// Load our class for namespacing.
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// wpcom handles the image sizes differently.
			require_once WPMU_PLUGIN_DIR . '/site-logo/inc/class-site-logo.php';
		} else {
			require __DIR__ . '/site-logo/inc/class-site-logo.php';
		}

		// Load template tags.
		require __DIR__ . '/site-logo/inc/functions.php';

		// Load backwards-compatible template tags.
		require __DIR__ . '/site-logo/inc/compat.php';
	}
}
add_action( 'init', 'site_logo_init' );

/**
 * When switching from a legacy theme that uses `site-logo` to a theme that uses `custom-logo`,
 * update the theme's custom logo if it doesn't already have one.
 *
 * @return void
 */
function jetpack_update_custom_logo_from_site_logo() {
	$site_logo = get_option( 'site_logo' );

	if ( current_theme_supports( 'custom-logo' ) && ! get_theme_mod( 'custom_logo' ) && $site_logo ) {
		set_theme_mod( 'custom_logo', $site_logo );
	}
}
add_action( 'after_switch_theme', 'jetpack_update_custom_logo_from_site_logo', 10, 0 );

/**
 * Transforms the legacy site_logo array, when present, into an attachment ID.
 *
 * The attachment ID is the format used for the site_logo option by the Site Logo block,
 * and the updated Jetpack site-logo feature.
 *
 * @since 9.9.0
 *
 * @param int|array $site_logo Option.
 * @return int
 */
function jetpack_site_logo_block_compat( $site_logo ) {
	if ( isset( $site_logo['id'] ) ) {
		remove_filter( 'option_site_logo', 'jetpack_site_logo_block_compat', 1 );
		update_option( 'site_logo', $site_logo['id'] );
		return $site_logo['id'];
	}

	return $site_logo;
}
add_filter( 'option_site_logo', 'jetpack_site_logo_block_compat', 1 );
