<?php
/**
 * Compatibility functions for the Web Stories plugin.
 * https://wordpress.org/plugins/web-stories/
 *
 * @since 9.2.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Web_Stories;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Filter to enable web stories built in open graph data from being output.
 * If Jetpack is already handling Open Graph Meta Tags, the Web Stories plugin will not output any.
 *
 * @param bool $enabled If web stories open graph data is enabled.
 *
 * @return bool
 */
function maybe_disable_open_graph( $enabled ) {
	/** This filter is documented in class.jetpack.php */
	$jetpack_enabled = apply_filters( 'jetpack_enable_open_graph', false );

	if ( $jetpack_enabled ) {
		$enabled = false;
	}

	return $enabled;
}
add_filter( 'web_stories_enable_open_graph_metadata', __NAMESPACE__ . '\maybe_disable_open_graph' );
add_filter( 'web_stories_enable_twitter_metadata', __NAMESPACE__ . '\maybe_disable_open_graph' );
