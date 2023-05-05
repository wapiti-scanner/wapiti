<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Auto update endpoint class.
 *
 * POST /sites/%s/maybe_auto_update
 */
class Jetpack_JSON_API_Maybe_Auto_Update_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var array
	 */
	protected $needed_capabilities = array( 'update_core', 'update_plugins', 'update_themes' );

	/**
	 * Update results.
	 *
	 * @var array
	 */
	protected $update_results = array();

	/**
	 * The result.
	 *
	 * @return array
	 */
	protected function result() {
		add_action( 'automatic_updates_complete', array( $this, 'get_update_results' ), 100, 1 );

		wp_maybe_auto_update();

		$result        = array();
		$result['log'] = $this->update_results;

		if ( empty( $result['log'] ) ) {
			$possible_reasons_for_failure = Jetpack_Autoupdate::get_possible_failures();

			if ( $possible_reasons_for_failure ) {
				$result['log']['error'] = $possible_reasons_for_failure;
			}
		}

		return $result;
	}

	/**
	 * Get update results.
	 *
	 * @param array $results - the results.
	 */
	public function get_update_results( $results ) {
		$this->update_results = $results;
	}

}
