<?php
/**
 * JITM's REST API Endpoints
 *
 * @package automattic/jetpack-jitm
 */

namespace Automattic\Jetpack\JITMS;

use Automattic\Jetpack\Connection\REST_Connector;
use WP_REST_Server;

/**
 * Register the JITM's REST API Endpoints and their callbacks.
 */
class Rest_Api_Endpoints {

	/**
	 * Declare the JITM's REST API endpoints.
	 */
	public static function register_endpoints() {

		register_rest_route(
			'jetpack/v4',
			'/jitm',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_jitm_message',
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'jetpack/v4',
			'/jitm',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => __CLASS__ . '::delete_jitm_message',
				'permission_callback' => __CLASS__ . '::delete_jitm_message_permission_callback',
			)
		);
	}

	/**
	 * Asks for a jitm, unless they've been disabled, in which case it returns an empty array
	 *
	 * @param WP_REST_Request $request The request object.
	 *
	 * @return array An array of jitms
	 */
	public static function get_jitm_message( $request ) {
		$jitm = JITM::get_instance();

		if ( ! $jitm->jitms_enabled() ) {
			return array();
		}

		return $jitm->get_messages( $request['message_path'], urldecode_deep( $request['query'] ), 'true' === $request['full_jp_logo_exists'] ? true : false );
	}

	/**
	 * Dismisses a jitm.
	 *
	 * @param WP_REST_Request $request The request object.
	 *
	 * @return bool Always True
	 */
	public static function delete_jitm_message( $request ) {
		$jitm = JITM::get_instance();

		if ( ! $jitm->jitms_enabled() ) {
			return true;
		}

		return $jitm->dismiss( $request['id'], $request['feature_class'] );
	}

	/**
	 * Verify that the user can dismiss JITM messages.
	 *
	 * @return bool|WP_Error True if user is able to dismiss JITM messages.
	 */
	public static function delete_jitm_message_permission_callback() {
		if ( current_user_can( 'read' ) ) {
			return true;
		}

		return new \WP_Error( 'invalid_user_permission_jetpack_delete_jitm_message', REST_Connector::get_user_permissions_error_msg(), array( 'status' => rest_authorization_required_code() ) );
	}

}
