<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Updates status class.
 *
 * GET /sites/%s/updates
 */
class Jetpack_JSON_API_Updates_Status extends Jetpack_JSON_API_Endpoint {
	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'manage_options';

	/**
	 * Endpoint callback.
	 *
	 * @return array|WP_Error
	 */
	protected function result() {

		wp_update_themes();
		wp_update_plugins();

		$update_data = wp_get_update_data();
		if ( ! isset( $update_data['counts'] ) ) {
			return new WP_Error( 'get_update_data_error', __( 'There was an error while getting the update data for this site.', 'jetpack' ), 500 );
		}

		$result = $update_data['counts'];

		include ABSPATH . WPINC . '/version.php'; // $wp_version;
		$result['wp_version'] = isset( $wp_version ) ? $wp_version : null; // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable

		if ( ! empty( $result['wordpress'] ) ) {
			$cur = get_preferred_from_update_core();
			if ( isset( $cur->response ) && $cur->response === 'upgrade' ) {
				$result['wp_update_version'] = $cur->current;
			}
		}

		$result['jp_version'] = JETPACK__VERSION;

		return $result;
	}
}
