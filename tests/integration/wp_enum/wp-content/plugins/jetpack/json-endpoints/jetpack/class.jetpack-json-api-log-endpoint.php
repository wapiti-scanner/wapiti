<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Jetpack log endpoint class.
 *
 * GET /sites/%s/jetpack-log
 */
class Jetpack_JSON_API_Jetpack_Log_Endpoint extends Jetpack_JSON_API_Endpoint {
	/**
	 * Needed capabilities.
	 *
	 * @var array
	 */
	protected $needed_capabilities = 'manage_options';

	/**
	 * The result.
	 *
	 * @return array
	 */
	protected function result() {
		$args  = $this->input();
		$event = ( isset( $args['event'] ) && is_string( $args['event'] ) ) ? $args['event'] : false;
		$num   = ( isset( $args['num'] ) ) ? (int) $args['num'] : false;

		return array(
			'log' => Jetpack::get_log( $event, $num ),
		);
	}
}
