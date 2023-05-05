<?php
/**
 * Class use to register REST API endpoints used by the WAF
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf;

use Automattic\Jetpack\Connection\REST_Connector;
use Automattic\Jetpack\Waf\Brute_Force_Protection\Brute_Force_Protection;
use WP_Error;
use WP_REST_Server;

/**
 * Defines our endponts.
 */
class REST_Controller {
	/**
	 * Register REST API endpoints.
	 *
	 * @return void
	 */
	public static function register_rest_routes() {
		register_rest_route(
			'jetpack/v4',
			'/waf',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::waf',
				'permission_callback' => __CLASS__ . '::waf_permissions_callback',
			)
		);

		register_rest_route(
			'jetpack/v4',
			'/waf',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::update_waf',
				'permission_callback' => __CLASS__ . '::waf_permissions_callback',
			)
		);

		register_rest_route(
			'jetpack/v4',
			'/waf/update-rules',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::update_rules',
				'permission_callback' => __CLASS__ . '::waf_permissions_callback',
			)
		);
	}

	/**
	 * Update rules endpoint
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public static function update_rules() {
		try {
			Waf_Rules_Manager::generate_automatic_rules();
			Waf_Rules_Manager::generate_rules();
		} catch ( Waf_Exception $e ) {
			return $e->get_wp_error();
		}

		return rest_ensure_response(
			array(
				'success' => true,
				'message' => __( 'Rules updated succesfully', 'jetpack-waf' ),
			)
		);
	}

	/**
	 * WAF Endpoint
	 *
	 * @return WP_REST_Response
	 */
	public static function waf() {
		return rest_ensure_response( Waf_Runner::get_config() );
	}

	/**
	 * Update WAF Endpoint
	 *
	 * @param WP_REST_Request $request The API request.
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public static function update_waf( $request ) {
		// Automatic Rules Enabled
		if ( isset( $request[ Waf_Rules_Manager::AUTOMATIC_RULES_ENABLED_OPTION_NAME ] ) ) {
			update_option( Waf_Rules_Manager::AUTOMATIC_RULES_ENABLED_OPTION_NAME, (bool) $request->get_param( Waf_Rules_Manager::AUTOMATIC_RULES_ENABLED_OPTION_NAME ) );
		}

		// IP Lists Enabled
		if ( isset( $request[ Waf_Rules_Manager::IP_LISTS_ENABLED_OPTION_NAME ] ) ) {
			update_option( Waf_Rules_Manager::IP_LISTS_ENABLED_OPTION_NAME, (bool) $request->get_param( Waf_Rules_Manager::IP_LISTS_ENABLED_OPTION_NAME ) );
		}

		// IP Block List
		if ( isset( $request[ Waf_Rules_Manager::IP_BLOCK_LIST_OPTION_NAME ] ) ) {
			update_option( Waf_Rules_Manager::IP_BLOCK_LIST_OPTION_NAME, $request[ Waf_Rules_Manager::IP_BLOCK_LIST_OPTION_NAME ] );
		}

		// IP Allow List
		if ( isset( $request[ Waf_Rules_Manager::IP_ALLOW_LIST_OPTION_NAME ] ) ) {
			update_option( Waf_Rules_Manager::IP_ALLOW_LIST_OPTION_NAME, $request[ Waf_Rules_Manager::IP_ALLOW_LIST_OPTION_NAME ] );
		}

		// Share Data
		if ( isset( $request[ Waf_Runner::SHARE_DATA_OPTION_NAME ] ) ) {
			update_option( Waf_Runner::SHARE_DATA_OPTION_NAME, (bool) $request[ Waf_Runner::SHARE_DATA_OPTION_NAME ] );
		}

		// Brute Force Protection
		if ( isset( $request['brute_force_protection'] ) ) {
			$enable_brute_force             = (bool) $request['brute_force_protection'];
			$brute_force_protection_toggled =
				$enable_brute_force
					? Brute_Force_Protection::enable()
					: Brute_Force_Protection::disable();

			if ( ! $brute_force_protection_toggled ) {
				return new WP_Error(
					$enable_brute_force
						? 'brute_force_protection_activation_failed'
						: 'brute_force_protection_deactivation_failed',
					$enable_brute_force
						? __( 'Brute force protection could not be activated.', 'jetpack-waf' )
						: __( 'Brute force protection could not be deactivated.', 'jetpack-waf' ),
					array( 'status' => 500 )
				);
			}
		}

		try {
			Waf_Runner::update_waf();
		} catch ( Waf_Exception $e ) {
			return $e->get_wp_error();
		}

		return self::waf();
	}

	/**
	 * WAF Endpoint Permissions Callback
	 *
	 * @return bool|WP_Error True if user can view the Jetpack admin page.
	 */
	public static function waf_permissions_callback() {
		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		return new WP_Error(
			'invalid_user_permission_manage_options',
			REST_Connector::get_user_permissions_error_msg(),
			array( 'status' => rest_authorization_required_code() )
		);
	}
}
