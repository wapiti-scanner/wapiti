<?php

namespace WPForms\Lite\Integrations\LiteConnect;

/**
 * Class LiteConnect for WPForms Lite.
 *
 * @since 1.7.4
 */
class LiteConnect extends \WPForms\Integrations\LiteConnect\LiteConnect {

	/**
	 * The Integration object.
	 *
	 * @since 1.7.4
	 *
	 * @var Integration
	 */
	private $integration;

	/**
	 * Send Entry Task object.
	 *
	 * @since 1.7.4
	 *
	 * @var SendEntryTask
	 */
	private $send_entry_task;

	/**
	 * Whether Lite Connect is enabled.
	 *
	 * @since 1.7.4
	 *
	 * @return bool
	 */
	public static function is_enabled() {

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName

		/**
		 * Determine whether LiteConnect is enabled on the WPForms > Settings admin page.
		 *
		 * @since 1.7.4
		 *
		 * @param bool $is_enabled Is LiteConnect enabled on WPForms > Settings page?
		 */
		return (bool) apply_filters( 'wpforms_lite_integrations_lite_connect_is_enabled', wpforms_setting( self::SETTINGS_SLUG ) );

		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Load the integration.
	 *
	 * @since 1.7.4
	 */
	public function load() {

		parent::load();

		// Do not load if user doesn't have permissions to update settings.
		if ( ! wpforms_current_user_can( wpforms_get_capability_manage_options() ) ) {
			return;
		}

		// Hooks.
		$this->hooks();

		// Process any pending submissions to the API, even if the Lite Connect integration is disabled.
		$this->send_entry_task = new SendEntryTask();

		// It won't load if the Lite Connect integration is not enabled.
		if ( ! self::is_enabled() ) {
			return;
		}

		// We always need to instance the Integration class as part of the load process for the Lite Connect integration.
		$this->integration = new Integration();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.4
	 */
	private function hooks() {

		// Add Lite Connect option to settings.
		add_filter( 'wpforms_settings_defaults', [ $this, 'settings_option' ] );

		// Automatically save the timestamp when Lite Connect was enabled first time.
		add_filter( 'wpforms_update_settings', [ $this, 'update_enabled_settings' ] );

	}

	/**
	 * Add "Lite Connect: Enable Entry Backups" to the WPForms Lite settings.
	 *
	 * @since 1.7.4
	 *
	 * @param array $settings WPForms settings.
	 *
	 * @return array
	 */
	public function settings_option( $settings ) {

		$setting = [
			self::SETTINGS_SLUG => [
				'id'            => self::SETTINGS_SLUG,
				'name'          => esc_html__( 'Lite Connect', 'wpforms-lite' ),
				'label'         => esc_html__( 'Enable Entry Backups', 'wpforms-lite' ),
				'type'          => 'toggle',
				'is-important'  => true,
				'control-class' => 'wpforms-setting-lite-connect-auto-save-toggle',
				'input-attr'    => 'disabled',
				'desc-on'       => sprintf(
					wp_kses( /* translators: %s - Upgrade to WPForms PRO landing page URL. */
						__( '<strong>Your form entries are not being stored locally, but are backed up remotely.</strong> If you <a href="%s" target="_blank" rel="noopener noreferrer" class="wpforms-upgrade-modal">upgrade to WPForms PRO</a>, you can restore your entries and they’ll be available in the WordPress dashboard.', 'wpforms-lite' ),
						[
							'a'      => [
								'href'   => [],
								'class'  => [],
								'target' => [],
								'rel'    => [],
							],
							'strong' => [],
						]
					),
					esc_url( wpforms_admin_upgrade_link( 'settings-lite-connect-enabled' ) )
				),
				'desc-off'      => sprintf(
					wp_kses( /* translators: %s - Upgrade to WPForms PRO landing page URL. */
						__( '<strong>Your form entries are not being stored in WordPress, and your entry backups are not active.</strong> If there\'s a problem with deliverability, you\'ll lose form entries. We recommend that you enable Entry Backups, especially if you\'re considering <a href="%s" target="_blank" rel="noopener noreferrer" class="wpforms-upgrade-modal">upgrading to WPForms PRO</a>.', 'wpforms-lite' ),
						[
							'a'      => [
								'href'   => [],
								'class'  => [],
								'target' => [],
								'rel'    => [],
							],
							'strong' => [],
						]
					),
					esc_url( wpforms_admin_upgrade_link( 'settings-lite-connect-disabled', 'Upgrade to WPForms Pro text Link' ) )
				),
			],
		];

		$settings['general'] = wpforms_list_insert_after( $settings['general'], 'license-key', $setting );

		return $settings;
	}

	/**
	 * Automatically save the additional info when Lite Connect was enabled first time.
	 *
	 * @since 1.7.4
	 *
	 * @param array $settings WPForms settings.
	 *
	 * @return array
	 */
	public function update_enabled_settings( $settings ) {

		if ( empty( $settings[ self::SETTINGS_SLUG ] ) ) {
			return $settings;
		}

		$since = self::SETTINGS_SLUG . '-since';
		$email = self::SETTINGS_SLUG . '-email';

		if ( empty( $settings[ $since ] ) ) {
			$settings[ $since ] = time();
		}

		if ( empty( $settings[ $email ] ) ) {
			$user               = wp_get_current_user();
			$settings[ $email ] = $user && ! empty( $user->user_email ) ? $user->user_email : get_option( 'admin_email' );
		}

		return $settings;
	}
}
