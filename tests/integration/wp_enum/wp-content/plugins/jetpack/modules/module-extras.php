<?php
/**
 * Load module code that is needed even when a module isn't active.
 * For example, if a module shouldn't be activatable unless certain conditions are met,
 * the code belongs in this file.
 *
 * @package automattic/jetpack
 */

/**
 * Features available all the time:
 *    - When in offline mode.
 *    - When connected to WordPress.com.
 */
$tools = array(
	// Always loaded, but only registered if theme supports it.
	'custom-post-types/comics.php',
	'custom-post-types/testimonial.php',
	'custom-post-types/nova.php',
	'geo-location.php',
	// Those oEmbed providers are always available.
	'shortcodes/facebook.php',
	'shortcodes/others.php',
	// Theme Tools.
	'theme-tools.php',
	'theme-tools/social-links.php',
	'theme-tools/random-redirect.php',
	'theme-tools/featured-content.php',
	'theme-tools/infinite-scroll.php',
	'theme-tools/responsive-videos.php',
	'theme-tools/site-logo.php',
	'theme-tools/site-breadcrumbs.php',
	'theme-tools/social-menu.php',
	'theme-tools/content-options.php',
	'theme-tools/devicepx.php',
	// Needed for VideoPress, so videos keep working in existing posts/pages when the module is deactivated.
	'videopress/class.videopress-gutenberg.php',
);

// Some features are only available when connected to WordPress.com.
$connected_tools = array(
	'calypsoify/class-jetpack-calypsoify.php',
	'cloudflare-analytics/cloudflare-analytics.php',
	'plugin-search.php',
	'scan/scan.php', // Shows Jetpack Scan alerts in the admin bar if threats found.
	'simple-payments/simple-payments.php',
	'wpcom-block-editor/class-jetpack-wpcom-block-editor.php',
	'wpcom-tos/wpcom-tos.php',
	// These oEmbed providers are available when connected to WordPress.com.
	// Starting from 2020-10-24, they need an authentication token, and that token is stored on WordPress.com.
	// More information: https://developers.facebook.com/docs/instagram/oembed/.
	'shortcodes/instagram.php',
);

// Add connected features to our existing list if the site is currently connected.
if ( Jetpack::is_connection_ready() ) {
	$tools = array_merge( $tools, $connected_tools );
}

/**
 * Filter extra tools (not modules) to include.
 *
 * @since 2.4.0
 * @since 5.4.0 can be used in multisite when Jetpack is not connected to WordPress.com and not in offline mode.
 *
 * @param array $tools Array of extra tools to include.
 */
$jetpack_tools_to_include = apply_filters( 'jetpack_tools_to_include', $tools );

if ( ! empty( $jetpack_tools_to_include ) ) {
	foreach ( $jetpack_tools_to_include as $tool ) {
		if ( file_exists( JETPACK__PLUGIN_DIR . '/modules/' . $tool ) ) {
			require_once JETPACK__PLUGIN_DIR . '/modules/' . $tool;
		}
	}
}

/**
 * Add the "(Jetpack)" suffix to the widget names
 *
 * @param string $widget_name Widget name.
 */
function jetpack_widgets_add_suffix( $widget_name ) {
	return sprintf(
		/* Translators: Placeholder is the name of a widget. */
		__( '%s (Jetpack)', 'jetpack' ),
		$widget_name
	);
}
add_filter( 'jetpack_widget_name', 'jetpack_widgets_add_suffix' );
