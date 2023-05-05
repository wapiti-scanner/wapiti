<?php
/**
 * Helper class providing various static utility functions for use in Search.
 *
 * @package    automattic/jetpack-wordads
 */

namespace Automattic\Jetpack\WordAds;

/**
 * Various helper functions for reuse throughout the WordAds code.
 */
class Helper {
	/**
	 * Get the current site's WordPress.com ID.
	 *
	 * @return int Blog ID.
	 */
	public static function get_wpcom_site_id() {
		// Returns local blog ID for a multi-site network.
		if ( defined( 'IS_WPCOM' ) && constant( 'IS_WPCOM' ) ) {
			return \get_current_blog_id();
		}

		// Returns cache site ID.
		return \Jetpack_Options::get_option( 'id' );
	}
}
