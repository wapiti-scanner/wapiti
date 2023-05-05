<?php

namespace WPForms\Integrations\WPorg;

use Language_Pack_Upgrader;
use Automatic_Upgrader_Skin;
use WPForms\Integrations\IntegrationInterface;

/**
 * Load translations from WordPress.org for the Lite version.
 *
 * @since 1.6.9
 */
class Translations implements IntegrationInterface {

	/**
	 * Full wp.org API URL for the plugin.
	 *
	 * @since 1.6.9
	 */
	const API_URL = 'https://api.wordpress.org/plugins/update-check/1.1/';

	/**
	 * Indicate if current integration is allowed to load.
	 *
	 * @since 1.6.9
	 *
	 * @return bool
	 */
	public function allow_load() {

		if ( ! is_admin() ) {
			return false;
		}

		// For WordPress versions 4.9.0-4.9.4 this file must be included before the current_user_can() check.
		require_once ABSPATH . 'wp-admin/includes/template.php';

		if ( ! current_user_can( 'install_languages' ) ) {
			return false;
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/translation-install.php';

		return wp_can_install_language_pack();
	}

	/**
	 * Load an integration.
	 *
	 * @since 1.6.9
	 */
	public function load() {

		// Download translations for all addons when language for the site has been changed.
		add_action( 'update_option_WPLANG', [ $this, 'download_translations' ] );
	}

	/**
	 * Get translation packages from the wp.org API.
	 *
	 * @since 1.6.9
	 *
	 * @return array
	 */
	private function get_translation_packages() {

		$plugin_data            = get_plugin_data( WPFORMS_PLUGIN_FILE );
		$plugin_data['Name']    = 'WPForms Lite';
		$plugin_data['Version'] = '9999.0';

		$request = wp_remote_post(
			self::API_URL,
			[
				'body' => [
					'plugins' => wp_json_encode(
						[
							'plugins' => [
								'wpforms-lite/wpforms.php' => $plugin_data,
							],
							'active'  => [],
						]
					),
					'locale'  => wp_json_encode( get_available_languages() ),
				],
			]
		);

		$code = wp_remote_retrieve_response_code( $request );
		$body = wp_remote_retrieve_body( $request );

		if ( $code !== 200 || $body === 'error' || is_wp_error( $body ) ) {
			return [];
		}

		$body = json_decode( $body, true );

		return ! empty( $body['translations'] ) ? $body['translations'] : [];
	}

	/**
	 * Download translations for all available languages.
	 *
	 * @since 1.6.9
	 */
	public function download_translations() {

		$translations = $this->get_translation_packages();

		if ( empty( $translations ) ) {
			return;
		}

		$skin     = new Automatic_Upgrader_Skin();
		$upgrader = new Language_Pack_Upgrader( $skin );

		foreach ( $translations as $language ) {
			// Sometimes a language can be passed as array.
			$this->download_package( (object) $language, $upgrader, $skin );
		}
	}

	/**
	 * Download translation for the language.
	 *
	 * @since 1.6.9
	 *
	 * @param object                  $language Language package.
	 * @param Language_Pack_Upgrader  $upgrader The instance of the core class used for updating/installing language packs (translations).
	 * @param Automatic_Upgrader_Skin $skin     Upgrader Skin for Automatic WordPress Upgrades.
	 */
	private function download_package( $language, Language_Pack_Upgrader $upgrader, Automatic_Upgrader_Skin $skin ) {

		if ( ! property_exists( $language, 'package' ) || empty( $language->package ) ) {
			return;
		}

		$skin->language_update = $language;

		$upgrader->run(
			[
				'package'                     => $language->package,
				'destination'                 => WP_LANG_DIR . '/plugins',
				'abort_if_destination_exists' => false,
				'is_multi'                    => true,
				'hook_extra'                  => [
					'language_update_type' => $language->type,
					'language_update'      => $language,
				],
			]
		);
	}
}
