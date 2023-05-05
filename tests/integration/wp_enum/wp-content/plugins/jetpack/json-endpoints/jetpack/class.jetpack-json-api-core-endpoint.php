<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Core endpoint class.
 *
 * POST /sites/%s/core
 * POST /sites/%s/core/update
 */
class Jetpack_JSON_API_Core_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'manage_options';

	/**
	 * New version.
	 *
	 * @var string
	 */
	protected $new_version;

	/**
	 *  An array of log strings.
	 *
	 * @var array
	 */
	protected $log;

	/**
	 * Return the result of the wp_version.
	 *
	 * @return array
	 */
	public function result() {
		global $wp_version;

		return array(
			'version'    => ( empty( $this->new_version ) ) ? $wp_version : $this->new_version,
			'autoupdate' => Jetpack_Options::get_option( 'autoupdate_core', false ),
			'log'        => $this->log,
		);
	}

}
