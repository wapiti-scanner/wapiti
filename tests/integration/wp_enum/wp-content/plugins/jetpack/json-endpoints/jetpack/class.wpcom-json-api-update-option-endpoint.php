<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Update option endpoint.
 */
class WPCOM_JSON_API_Update_Option_Endpoint extends WPCOM_JSON_API_Get_Option_Endpoint {
	/**
	 * The option value.
	 *
	 * @var string
	 */
	public $option_value;

	/**
	 * Endpoint callback.
	 *
	 * @return array
	 */
	public function result() {
		if ( $this->site_option ) {
			update_site_option( $this->option_name, $this->option_value );
		} else {
			update_option( $this->option_name, $this->option_value );
		}
		return parent::result();
	}

	/**
	 * Validate the input.
	 *
	 * @param object $object - the object we're validating.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_input( $object ) {
		$input      = $this->input();
		$query_args = $this->query_args();
		if ( ! isset( $input['option_value'] ) || is_array( $input['option_value'] ) ) {
			return new WP_Error( 'option_value_not_set', __( 'You must specify an option_value', 'jetpack' ) );
		}
		if ( $query_args['is_array'] ) {
			// When converted back from JSON, the value is an object.
			// Cast it to an array for options that expect arrays.
			$this->option_value = (array) $input['option_value'];
		} else {
			$this->option_value = $input['option_value'];
		}

		return parent::validate_input( $object );
	}
}
