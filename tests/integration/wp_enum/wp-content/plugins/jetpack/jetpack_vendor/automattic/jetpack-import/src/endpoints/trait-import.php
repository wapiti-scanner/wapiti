<?php
/**
 * Jetpack Import unique import ID.
 *
 * @package automattic/jetpack-import
 */

namespace Automattic\Jetpack\Import\Endpoints;

/**
 * Import trait. Base class for all import endpoints.
 */
trait Import {

	/**
	 * REST API namespace.
	 *
	 * @var string
	 */
	private static $rest_namespace = 'jetpack/v4/import';

	/**
	 * Registers the routes for the objects of the controller.
	 *
	 * @see WP_REST_Controller::register_rest_route()
	 */
	public function register_routes() {
		register_rest_route(
			self::$rest_namespace,
			'/' . $this->rest_base,
			$this->get_route_options()
		);
	}

	/**
	 * Ensure that the user has permissions to import.
	 *
	 * @return bool|\WP_Error
	 */
	public function import_permissions_callback() {
		// The permission check is done in the REST API authentication. It's the same
		// as the one used in wp-admin/import.php.
		if ( \current_user_can( 'import' ) ) {
			return true;
		}

		$error_msg = \esc_html__(
			'You are not allowed to perform this action.',
			'jetpack-import'
		);

		return new \WP_Error( 'rest_forbidden', $error_msg, array( 'status' => \rest_authorization_required_code() ) );
	}

	/**
	 * Get the register route options.
	 *
	 * @see register_rest_route()
	 *
	 * @return array The options.
	 */
	protected function get_route_options() {
		return array(
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'create_item' ),
				'permission_callback' => array( $this, 'import_permissions_callback' ),
				'args'                => $this->get_endpoint_args_for_item_schema( \WP_REST_Server::CREATABLE ),
			),
			'allow_batch' => $this->allow_batch,
			'schema'      => array( $this, 'get_public_item_schema' ),
		);
	}

	/**
	 * Ensure that the HTTP status is correct.
	 *
	 * @param WP_Error $response   Response error object.
	 * @param int      $error_code Error code.
	 * @param int      $status     HTTP status.
	 */
	protected function ensure_http_status( $response, $error_code, $status ) {
		if ( is_wp_error( $response ) && in_array( $error_code, $response->get_error_codes(), true ) ) {
			$data = $response->get_error_data( $error_code );

			if ( isset( $data['status'] ) ) {
				$data['status'] = $status;

				$response->add_data( $data );
			}
		}

		return $response;
	}
}
