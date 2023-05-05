<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * JPS WooCommerce connect endpoint.
 */
class Jetpack_JSON_API_JPS_WooCommerce_Connect_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'manage_options';

	/**
	 * The result.
	 *
	 * @return array|WP_Error
	 */
	public function result() {
		$input       = $this->input();
		$helper_data = get_option( 'woocommerce_helper_data', array() );

		if ( ! empty( $helper_data['auth'] ) ) {
			return new WP_Error(
				'already_configured',
				__( 'WooCommerce auth data is already set.', 'jetpack' )
			);
		}

		// Only update the auth field for `woocommerce_helper_data` instead of blowing out the entire option.
		$helper_data['auth'] = array(
			'user_id'             => $input['user_id'],
			'site_id'             => $input['site_id'],
			'updated'             => time(),
			'access_token'        => $input['access_token'],
			'access_token_secret' => $input['access_token_secret'],
		);

		$updated = update_option(
			'woocommerce_helper_data',
			$helper_data
		);

		return array(
			'success' => $updated,
		);
	}

	/**
	 * Validate input.
	 *
	 * @param object $object - the object we're validating.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_input( $object ) {
		$input = $this->input();

		if ( empty( $input['access_token'] ) ) {
			return new WP_Error( 'input_error', __( 'access_token is required', 'jetpack' ) );
		}

		if ( empty( $input['access_token_secret'] ) ) {
			return new WP_Error( 'input_error', __( 'access_token_secret is required', 'jetpack' ) );
		}

		if ( empty( $input['user_id'] ) ) {
			return new WP_Error( 'input_error', __( 'user_id is required', 'jetpack' ) );
		}

		if ( empty( $input['site_id'] ) ) {
			return new WP_Error( 'input_error', __( 'site_id is required', 'jetpack' ) );
		}

		return parent::validate_input( $object );
	}
}
