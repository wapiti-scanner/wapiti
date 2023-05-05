<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Translations endpoint class.
 *
 * GET /sites/%s/translations
 * POST /sites/%s/translations
 * POST /sites/%s/translations/update
 */
class Jetpack_JSON_API_Translations_Endpoint extends Jetpack_JSON_API_Endpoint {
	/**
	 * Needed capabilities.
	 *
	 * @var array
	 */
	protected $needed_capabilities = array( 'update_core', 'update_plugins', 'update_themes' );

	/**
	 * The log.
	 *
	 * @var array
	 */
	protected $log;

	/**
	 * If we're successful.
	 *
	 * @var bool
	 */
	protected $success;

	/**
	 * API Endpoint.
	 *
	 * @return array
	 */
	public function result() {
		return array(
			'translations' => wp_get_translation_updates(),
			'autoupdate'   => Jetpack_Options::get_option( 'autoupdate_translations', false ),
			'log'          => $this->log,
			'success'      => $this->success,
		);
	}
}
