<?php
/**
 * VideoPress Settings Endpoint
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use WP_Error;
use WP_REST_Response;
use WP_REST_Server;

/**
 * Rest API class for fetching and setting site settings related to VideoPress.
 */
class VideoPress_Rest_Api_V1_Settings {
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
			'settings',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( static::class, 'get_settings' ),
					'permission_callback' => function () {
						return current_user_can( 'manage_options' );
					},
				),
				array(
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => array( static::class, 'update_settings' ),
					'permission_callback' => function () {
						return Data::can_perform_action() && current_user_can( 'manage_options' );
					},
					'args'                => array(
						'videopress_videos_private_for_site' => array(
							'description'       => __( 'If the VideoPress videos should be private by default', 'jetpack-videopress-pkg' ),
							'type'              => 'boolean',
							'required'          => true,
							'sanitize_callback' => 'rest_sanitize_boolean',
						),
					),
				),
			)
		);
	}

	/**
	 * Returns the value of the VideoPress settings.
	 *
	 * @return WP_Rest_Response - The response object.
	 */
	public static function get_settings() {
		$has_connected_owner = Data::has_connected_owner();
		if ( ! $has_connected_owner ) {
			return rest_ensure_response(
				new WP_Error(
					'owner_not_connected',
					'User not connected.',
					array(
						'code'        => 503,
						'connect_url' => Admin_UI::get_admin_page_url(),
					)
				)
			);
		}

		$blog_id = Data::get_blog_id();
		if ( ! $blog_id ) {
			return rest_ensure_response(
				new WP_Error( 'site_not_registered', 'Site not registered.', 503 )
			);
		}

		$status = 200;
		$data   = Data::get_videopress_settings();

		return rest_ensure_response(
			new WP_REST_Response( $data, $status )
		);
	}

	/**
	 * Updates the value of the VideoPress settings when a new value
	 * is present on the request body.
	 *
	 * @param WP_REST_Request $request the request object.
	 * @return WP_Rest_Response - The response object.
	 */
	public static function update_settings( $request ) {
		$has_connected_owner = Data::has_connected_owner();
		if ( ! $has_connected_owner ) {
			return rest_ensure_response(
				new WP_Error(
					'owner_not_connected',
					'User not connected.',
					array(
						'code'        => 503,
						'connect_url' => Admin_UI::get_admin_page_url(),
					)
				)
			);
		}

		$blog_id = Data::get_blog_id();
		if ( ! $blog_id ) {
			return rest_ensure_response(
				new WP_Error( 'site_not_registered', 'Site not registered.', 503 )
			);
		}

		$json_params = $request->get_json_params();

		// We are sure that the param is set because it's required by the request
		update_option( 'videopress_private_enabled_for_site', boolval( $json_params['videopress_videos_private_for_site'] ) );

		return rest_ensure_response(
			array(
				'code'    => 'success',
				'message' => __( 'VideoPress settings updated successfully.', 'jetpack-videopress-pkg' ),
				'data'    => 200,
			)
		);
	}
}
