<?php
/**
 * Get search stats for use in the wp-admin dashboard.
 *
 * @package automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search;

use Automattic\Jetpack\Connection\Client;
use Jetpack_Options;

/**
 * Search stats (e.g. post count, post type breakdown)
 */
class Stats {
	/**
	 * Get stats from the WordPress.com API for the current blog ID.
	 */
	public function get_stats_from_wpcom() {
		$blog_id = Jetpack_Options::get_option( 'id' );

		if ( ! is_numeric( $blog_id ) ) {
			return null;
		}

		$response = Client::wpcom_json_api_request_as_blog(
			'/sites/' . (int) $blog_id . '/jetpack-search/stats',
			'2',
			array(),
			null,
			'wpcom'
		);

		return $response;
	}
}
