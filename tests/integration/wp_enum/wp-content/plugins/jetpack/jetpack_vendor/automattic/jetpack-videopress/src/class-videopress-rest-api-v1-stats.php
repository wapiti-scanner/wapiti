<?php
/**
 * VideoPress Stats Endpoints
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use WP_REST_Response;

/**
 * VideoPress stats rest api class
 */
class VideoPress_Rest_Api_V1_Stats {
	/**
	 * Initializes the endpoints
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'rest_api_init', array( static::class, 'register_rest_endpoints' ) );
	}

	/**
	 * Register the REST API routes.
	 *
	 * @return void
	 */
	public static function register_rest_endpoints() {
		/**
		 * Basic stats.
		 */
		register_rest_route(
			'videopress/v1',
			'stats',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static::class . '::get_stats',
				'permission_callback' => static::class . '::permissions_callback',
			)
		);

		/**
		 * Stats to be featured by My Jetpack.
		 */
		register_rest_route(
			'videopress/v1',
			'stats/featured',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static::class . '::get_featured_stats',
				'permission_callback' => static::class . '::permissions_callback',
			)
		);
	}

	/**
	 * Checks wether the user have permissions to see stats
	 *
	 * @return boolean
	 */
	public static function permissions_callback() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Endpoint for getting the general VideoPress stats for the site.
	 *
	 * Returns the plays for all the videos, for today and since the beggining of times.
	 *
	 * @return WP_Rest_Response - The response object.
	 */
	public static function get_stats() {
		$today_plays = Stats::get_today_plays();

		if ( is_wp_error( $today_plays ) ) {
			// TODO: Improve status code.
			return rest_ensure_response( $today_plays );
		}

		$data = array(
			'plays' => array(
				'today' => $today_plays,
			),
		);

		return rest_ensure_response( $data );
	}

	/**
	 * Provides the stats that will be featured by My Jetpack.
	 *
	 * @return WP_Rest_Response - The response object.
	 */
	public static function get_featured_stats() {
		$featured_stats = Stats::get_featured_stats();
		return rest_ensure_response( $featured_stats );
	}
}
