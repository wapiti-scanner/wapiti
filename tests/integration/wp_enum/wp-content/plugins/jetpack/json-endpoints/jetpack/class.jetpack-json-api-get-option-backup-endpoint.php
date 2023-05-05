<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Get option backup endpoint.
 *
 * /sites/%s/options/backup      -> $blog_id
 */
class Jetpack_JSON_API_Get_Option_Backup_Endpoint extends Jetpack_JSON_API_Endpoint {
	/**
	 * Needed capabilities.
	 *
	 * @var array
	 */
	protected $needed_capabilities = array(); // This endpoint is only accessible using a site token

	/**
	 * Option names.
	 *
	 * @var string
	 */
	protected $option_names;

	/**
	 * Validate input.
	 *
	 * @param object $object - unused.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_input( $object ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$query_args = $this->query_args();

		if ( empty( $query_args['name'] ) ) {
			return new WP_Error( 'option_name_not_specified', __( 'You must specify an option name', 'jetpack' ), 400 );
		}

		if ( is_array( $query_args['name'] ) ) {
			$this->option_names = $query_args['name'];
		} else {
			$this->option_names = array( $query_args['name'] );
		}

		return true;
	}

	/**
	 * The result.
	 */
	protected function result() {
		// Disable Sync as this is a read-only operation and triggered by sync activity.
		\Automattic\Jetpack\Sync\Actions::mark_sync_read_only();

		$options = array_map( array( $this, 'get_option_row' ), $this->option_names );
		return array( 'options' => $options );
	}

	/**
	 * Get options row.
	 *
	 * @param string $name - name of the row.
	 *
	 * @return object|null Database query result or null on failure.
	 */
	private function get_option_row( $name ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( "select * from `{$wpdb->options}` where option_name = %s", $name ) );
	}

}
