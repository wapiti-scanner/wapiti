<?php
/**
 * A Licensing Endpoints class for Jetpack.
 *
 * @package automattic/jetpack-licensing
 */

namespace Automattic\Jetpack\Licensing;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Licensing;
use Automattic\Jetpack\Status\Visitor;
use Jetpack_Options;
use WP_Error;

/**
 * Class Endpoints.
 * Helper class that is responsible for registering and responding to licensing endpoint requests.
 *
 * @since 1.7.0
 */
class Endpoints {
	/**
	 * This property stores the localized "Insufficient Permissions" error message.
	 *
	 * @var string Generic error message when user is not allowed to perform an action.
	 */
	private static $user_permissions_error_msg;

	/**
	 * Constructor.
	 */
	public function __construct() {
		self::$user_permissions_error_msg = esc_html__(
			'You do not have the correct user permissions to perform this action.
			Please contact your site admin if you think this is a mistake.',
			'jetpack-licensing'
		);
	}

	/**
	 * Declare the endpoints for the licensing package.
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 10.9.0
	 */
	public function register_endpoints() {
		/*
		 * Get and update the last licensing error message.
		 */
		register_rest_route(
			'jetpack/v4',
			'/licensing/error',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => __CLASS__ . '::get_licensing_error',
					'permission_callback' => __CLASS__ . '::can_manage_options_check',
				),
				array(
					'methods'             => \WP_REST_Server::EDITABLE,
					'callback'            => __CLASS__ . '::update_licensing_error',
					'permission_callback' => __CLASS__ . '::can_manage_options_check',
					'args'                => array(
						'error' => array(
							'required'          => true,
							'type'              => 'string',
							'validate_callback' => __CLASS__ . '::validate_string',
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				),
			)
		);

		/**
		 * Sets a license. This is still used as part of the first pass at licensing done for partners.
		 *
		 * See https://github.com/Automattic/jetpack/pull/23687 for more details.
		 */
		register_rest_route(
			'jetpack/v4',
			'/licensing/set-license',
			array(
				'methods'             => \WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::set_jetpack_license',
				'permission_callback' => __CLASS__ . '::set_jetpack_license_key_permission_check',
				'args'                => array(
					'license' => array(
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => __CLASS__ . '::validate_string',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		/**
		 * Get Jetpack user licenses.
		 */
		register_rest_route(
			'jetpack/v4',
			'licensing/user/licenses',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_user_licenses',
				'permission_callback' => __CLASS__ . '::user_licensing_permission_check',
			)
		);

		/**
		 * Get Jetpack user license counts.
		 */
		register_rest_route(
			'jetpack/v4',
			'licensing/user/counts',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::get_user_license_counts',
				'permission_callback' => __CLASS__ . '::user_licensing_permission_check',
			)
		);

		/**
		 * Update user-licensing activation notice dismiss info.
		 */
		register_rest_route(
			'jetpack/v4',
			'licensing/user/activation-notice-dismiss',
			array(
				'methods'             => \WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::update_licensing_activation_notice_dismiss',
				'permission_callback' => __CLASS__ . '::user_licensing_permission_check',
				'args'                => array(
					'last_detached_count' => array(
						'required'          => true,
						'type'              => 'integer',
						'validate_callback' => __CLASS__ . '::validate_non_neg_int',
					),
				),
			)
		);

		/**
		 * Attach licenses to user account
		 */
		register_rest_route(
			'jetpack/v4',
			'/licensing/attach-licenses',
			array(
				'methods'             => \WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::attach_jetpack_licenses',
				'permission_callback' => __CLASS__ . '::user_licensing_permission_check',
				'args'                => array(
					'licenses' => array(
						'required' => true,
						'type'     => 'array',
						'items'    => array(
							'type' => 'string',
						),
					),
				),
			)
		);
	}

	/**
	 * Verify that the user can set a Jetpack license key
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 9.5.0
	 *
	 * @return bool|WP_Error True if user is able to set a Jetpack license key
	 */
	public static function set_jetpack_license_key_permission_check() {
		if ( Licensing::instance()->is_licensing_input_enabled() ) {
			return true;
		}

		return new WP_Error( 'invalid_user_permission_set_jetpack_license_key', self::$user_permissions_error_msg, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Verify that user can view and update user-licensing data.
	 *
	 * @since 1.7.0
	 *
	 * @return bool Whether the user is currently connected and they are the connection owner.
	 */
	public static function user_licensing_permission_check() {
		$connection_manager = new Connection_Manager( 'jetpack' );

		if ( $connection_manager->is_user_connected() && $connection_manager->is_connection_owner() ) {
			return true;
		}

		return new WP_Error( 'invalid_permission_manage_user_licenses', self::$user_permissions_error_msg, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Verify that user can manage_options
	 *
	 * @since 1.7.0
	 *
	 * @return bool Whether user has the capability 'manage_options'.
	 */
	public static function can_manage_options_check() {
		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		return new WP_Error( 'invalid_user_permission_view_admin', self::$user_permissions_error_msg, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Validates that the parameter is a string.
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 4.3.0
	 *
	 * @param string          $value Value to check.
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @param string          $param Name of the parameter passed to endpoint holding $value.
	 *
	 * @return bool|WP_Error
	 */
	public static function validate_string( $value, $request, $param ) {
		if ( ! is_string( $value ) ) {
			/* translators: %s: The literal parameter name. Should not be translated. */
			return new WP_Error( 'invalid_param', sprintf( esc_html__( '%s must be a string.', 'jetpack-licensing' ), $param ) );
		}
		return true;
	}

	/**
	 * Validates that the parameter is a non-negative integer (includes 0).
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 10.4.0
	 *
	 * @param int             $value Value to check.
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @param string          $param Name of the parameter passed to endpoint holding $value.
	 *
	 * @return bool|WP_Error
	 */
	public static function validate_non_neg_int( $value, $request, $param ) {
		if ( ! is_numeric( $value ) || $value < 0 ) {
			return new WP_Error(
				'invalid_param',
				/* translators: %s: The literal parameter name. Should not be translated. */
				sprintf( esc_html__( '%s must be a non-negative integer.', 'jetpack-licensing' ), $param )
			);
		}
		return true;
	}

	/**
	 * Update the last licensing error message.
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 9.0.0
	 *
	 * @param WP_REST_Request $request The request.
	 *
	 * @return bool true.
	 */
	public static function update_licensing_error( $request ) {
		Licensing::instance()->log_error( $request['error'] );

		return true;
	}

	/**
	 * Get the last licensing error message, if any.
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 9.0.0
	 *
	 * @return string Licensing error message or empty string.
	 */
	public static function get_licensing_error() {
		return Licensing::instance()->last_error();
	}

	/**
	 * Set a Jetpack license
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 9.6.0
	 *
	 * @param WP_REST_Request $request The request.
	 *
	 * @return WP_REST_Response|WP_Error A response object if the option was successfully updated, or a WP_Error if it failed.
	 */
	public static function set_jetpack_license( $request ) {
		$license = trim( sanitize_text_field( $request['license'] ) );

		if ( Licensing::instance()->append_license( $license ) ) {
			return rest_ensure_response( array( 'code' => 'success' ) );
		}

		return new WP_Error(
			'setting_license_key_failed',
			esc_html__( 'Could not set this license key. Please try again.', 'jetpack-licensing' ),
			array( 'status' => 500 )
		);
	}

	/**
	 * Gets the users licenses.
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 10.4.0
	 *
	 * @return string|WP_Error A JSON object of user licenses if the request was successful, or a WP_Error otherwise.
	 */
	public static function get_user_licenses() {
		$wpcom_request = Client::wpcom_json_api_request_as_user(
			'/jetpack-licensing/user/licenses',
			'2',
			array(
				'method'  => 'GET',
				'headers' => array(
					'Content-Type'    => 'application/json',
					'X-Forwarded-For' => ( new Visitor() )->get_ip( true ),
				),
			)
		);

		$response_code = wp_remote_retrieve_response_code( $wpcom_request );
		if ( 200 === $response_code ) {
			$licenses = json_decode( wp_remote_retrieve_body( $wpcom_request ) );
			return $licenses;
		} else {
			return new WP_Error(
				'failed_to_fetch_data',
				esc_html__( 'Unable to fetch the requested data.', 'jetpack-licensing' ),
				array( 'status' => $response_code )
			);
		}
	}

	/**
	 * Gets the users licenses counts.
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 10.4.0
	 *
	 * @return string|WP_Error A JSON object of user license counts if the request was successful, or a WP_Error otherwise.
	 */
	public static function get_user_license_counts() {
		$wpcom_request = Client::wpcom_json_api_request_as_user(
			'/jetpack-licensing/user/licenses/counts',
			'2',
			array(
				'method'  => 'GET',
				'headers' => array(
					'Content-Type'    => 'application/json',
					'X-Forwarded-For' => ( new Visitor() )->get_ip( true ),
				),
			)
		);

		$response_code = wp_remote_retrieve_response_code( $wpcom_request );
		if ( 200 === $response_code ) {
			$license_counts = json_decode( wp_remote_retrieve_body( $wpcom_request ) );
			return $license_counts;
		} else {
			return new WP_Error(
				'failed_to_fetch_data',
				esc_html__( 'Unable to fetch the requested data.', 'jetpack-licensing' ),
				array( 'status' => $response_code )
			);
		}
	}

	/**
	 * Update the user-licenses activation notice dismissal data.
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 10.4.0
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return array|WP_Error
	 */
	public static function update_licensing_activation_notice_dismiss( $request ) {

		if ( ! isset( $request['last_detached_count'] ) ) {
			return new WP_Error( 'invalid_param', esc_html__( 'Missing parameter "last_detached_count".', 'jetpack-licensing' ), array( 'status' => 404 ) );
		}

		$default             = array(
			'last_detached_count' => null,
			'last_dismissed_time' => null,
		);
		$last_detached_count = ( '' === $request['last_detached_count'] )
			? $default['last_detached_count']
			: $request['last_detached_count'];
		$last_dismissed_time = ( '' === $request['last_detached_count'] )
			? $default['last_dismissed_time']
			// Use UTC timezone and convert to ISO8601 format(DateTime::W3C) for best compatibility with JavaScript Date in all browsers.
			: ( new \DateTime( 'NOW', new \DateTimeZone( 'UTC' ) ) )->format( \DateTime::W3C );

		$notice_data = array(
			'last_detached_count' => $last_detached_count,
			'last_dismissed_time' => $last_dismissed_time,
		);

		Jetpack_Options::update_option( 'licensing_activation_notice_dismiss', $notice_data, true );
		return rest_ensure_response( $notice_data );
	}

	/**
	 * Attach Jetpack licenses
	 *
	 * @since 1.7.0
	 *
	 * @since-jetpack 10.4.0
	 *
	 * @param WP_REST_Request $request The request.
	 *
	 * @return WP_REST_Response|WP_Error A response object
	 */
	public static function attach_jetpack_licenses( $request ) {
		$licenses = array_map(
			function ( $license ) {
				return trim( sanitize_text_field( $license ) );
			},
			$request['licenses']
		);
		return rest_ensure_response( Licensing::instance()->attach_licenses( $licenses ) );
	}
}
