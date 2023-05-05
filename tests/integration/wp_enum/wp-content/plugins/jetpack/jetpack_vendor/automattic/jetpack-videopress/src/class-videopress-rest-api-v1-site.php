<?php
/**
 * VideoPress Site Info Endpoint
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

/**
 * VideoPress rest api class for fetching site information
 */
class VideoPress_Rest_Api_V1_Site {
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
		register_rest_route(
			'videopress/v1',
			'site',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static::class . '::get_site_info',
				'permission_callback' => static::class . '::permissions_callback',
			)
		);
	}

	/**
	 * Checks wether the user have permissions to see the site info
	 *
	 * @return boolean
	 */
	public static function permissions_callback() {
		return current_user_can( 'read' ); // TODO: confirm this
	}

	/**
	 * Returns all the site information usually provided by Jetpack, without relying on Jetpack
	 *
	 * @return WP_Rest_Response The response object.
	 */
	public static function get_site_info() {
		$data = Site::get_site_info();
		return rest_ensure_response( $data );
	}
}
