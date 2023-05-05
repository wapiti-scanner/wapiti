<?php
/**
 * The WordAds Rest Controller class.
 * Registers the REST routes for WordAds.
 *
 * @package automattic/jetpack-wordads
 */

namespace Automattic\Jetpack\WordAds;

use Automattic\Jetpack\Modules;
use Jetpack_Options;
use WP_Error;
use WP_REST_Request;
use WP_REST_Server;

/**
 * Registers the REST routes for WordAds.
 */
class REST_Controller {
	/**
	 * Whether it's run on WPCOM.
	 *
	 * @var bool
	 */
	protected $is_wpcom;

	/**
	 * Constructor
	 *
	 * @param bool $is_wpcom - Whether it's run on WPCOM.
	 */
	public function __construct( $is_wpcom = false ) {
		$this->is_wpcom = $is_wpcom;
	}

	/**
	 * Registers the REST routes for WordAds.
	 *
	 * @access public
	 * @static
	 */
	public function register_rest_routes() {
		register_rest_route(
			'jetpack/v4',
			'/wordads/settings',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'update_settings' ),
				'permission_callback' => array( $this, 'require_admin_privilege_callback' ),
			)
		);
		register_rest_route(
			'jetpack/v4',
			'/wordads/settings',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_settings' ),
				'permission_callback' => array( $this, 'require_admin_privilege_callback' ),
			)
		);
	}

	/**
	 * Only administrators can access the API.
	 *
	 * @return bool|WP_Error True if a blog token was used to sign the request, WP_Error otherwise.
	 */
	public function require_admin_privilege_callback() {
		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		$error_msg = esc_html__(
			'You are not allowed to perform this action.',
			'jetpack-wordads'
		);

		return new WP_Error( 'rest_forbidden', $error_msg, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * POST `jetpack/v4/wordads/settings`
	 *
	 * @param WP_REST_Request $request - REST request.
	 */
	public function update_settings( $request ) {
		$request_body = $request->get_json_params();

		$module_active = isset( $request_body['module_active'] ) ? (bool) $request_body['module_active'] : null;

		$errors = array();
		if ( $module_active !== null ) {
			$module_active_updated = ( new Modules() )->update_status( Package::SLUG, $module_active, false, false );
			if ( is_wp_error( $module_active_updated ) ) {
				$errors['module_active'] = $module_active_updated;
			}
		}

		if ( ! empty( $errors ) ) {
			return new WP_Error(
				'some_updated',
				sprintf(
					/* translators: %s are the setting name that not updated. */
					__( 'Some settings ( %s ) not updated.', 'jetpack-wordads' ),
					implode(
						',',
						array_keys( $errors )
					)
				),
				array( 'status' => 400 )
			);
		}

		return rest_ensure_response( $this->get_settings() );
	}

	/**
	 * GET `jetpack/v4/wordads/settings`
	 */
	public function get_settings() {
		return rest_ensure_response(
			array(
				'module_active' => ( new Modules() )->is_active( Package::SLUG ),
			)
		);
	}

	/**
	 * Get blog id
	 */
	protected function get_blog_id() {
		return $this->is_wpcom ? get_current_blog_id() : Jetpack_Options::get_option( 'id' );
	}

}
