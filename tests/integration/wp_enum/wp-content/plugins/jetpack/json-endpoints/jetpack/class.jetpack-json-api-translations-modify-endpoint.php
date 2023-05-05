<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Translations modify endpoint class.
 * POST /sites/%s/translation
 * POST /sites/%s/translations/update
 */
class Jetpack_JSON_API_Translations_Modify_Endpoint extends Jetpack_JSON_API_Translations_Endpoint {

	/**
	 * The action.
	 *
	 * @var string
	 */
	protected $action = 'default_action';

	/**
	 * The new version.
	 *
	 * @var string
	 */
	protected $new_version;

	/**
	 * The log.
	 *
	 * @var array
	 */
	protected $log;

	/**
	 * Run the default action.
	 *
	 * @return true
	 */
	public function default_action() {
		$args = $this->input();

		if ( isset( $args['autoupdate'] ) && is_bool( $args['autoupdate'] ) ) {
			Jetpack_Options::update_option( 'autoupdate_translations', $args['autoupdate'] );
		}

		return true;
	}

	/**
	 * Update the translations.
	 */
	protected function update() {
		include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

		$upgrader = new Language_Pack_Upgrader( new Automatic_Upgrader_Skin() );
		$result   = $upgrader->bulk_upgrade();

		$this->log     = $upgrader->skin->get_upgrade_messages();
		$this->success = ( ! is_wp_error( $result ) ) ? (bool) $result : false;
	}
}
