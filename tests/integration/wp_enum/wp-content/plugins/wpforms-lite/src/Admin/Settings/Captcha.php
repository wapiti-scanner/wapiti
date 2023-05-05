<?php

namespace WPForms\Admin\Settings;

use WPForms\Admin\Notice;
use WPForms\Admin\Settings\Captcha\Page;

/**
 * CAPTCHA setting page.
 *
 * @since 1.6.4
 * @deprecated 1.8.0
 */
class Captcha {

	/**
	 * Slug identifier for admin page view.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 *
	 * @var string
	 */
	const VIEW = 'captcha';

	/**
	 * The hCaptcha javascript URL-resource.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	const HCAPTCHA_API_URL = 'https://hcaptcha.com/1/api.js';

	/**
	 * The reCAPTCHA javascript URL-resource.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	const RECAPTCHA_API_URL = 'https://www.google.com/recaptcha/api.js';

	/**
	 * Saved CAPTCHA settings.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Initialize class.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	public function init() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin', 'WPForms\Admin\Settings\Captcha\Page::init()' );

		( new Page() )->init();
	}

	/**
	 * Init CAPTCHA settings.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	public function init_settings() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin', 'WPForms\Admin\Settings\Captcha\Page::init_settings()' );

		( new Page() )->init_settings();
	}

	/**
	 * Hooks.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	public function hooks() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin', 'WPForms\Admin\Settings\Captcha\Page::hooks()' );

		( new Page() )->hooks();
	}

	/**
	 * Register CAPTCHA settings tab.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 *
	 * @param array $tabs Admin area tabs list.
	 *
	 * @return array
	 */
	public function register_settings_tabs( $tabs ) {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin', 'WPForms\Admin\Settings\Captcha\Page::register_settings_tabs()' );

		return ( new Page() )->register_settings_tabs( $tabs );
	}

	/**
	 * Register CAPTCHA settings fields.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 *
	 * @param array $settings Admin area settings list.
	 *
	 * @return array
	 */
	public function register_settings_fields( $settings ) {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin', 'WPForms\Admin\Settings\Captcha\Page::register_settings_fields()' );

		return ( new Page() )->register_settings_fields( $settings );
	}

	/**
	 * Re-init CAPTCHA settings when plugin settings were updated.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	public function updated() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin', 'WPForms\Admin\Settings\Captcha\Page::updated()' );

		( new Page() )->updated();
	}

	/**
	 * Display notice about the CAPTCHA preview.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	protected function notice() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin' );

		if (
			! wpforms_is_admin_page( 'settings', self::VIEW ) ||
			! $this->is_captcha_preview_ready()
		) {
			return;
		}

		Notice::info( esc_html__( 'A preview of your CAPTCHA is displayed below. Please view to verify the CAPTCHA settings are correct.', 'wpforms-lite' ) );
	}

	/**
	 * Enqueue assets for the CAPTCHA settings page.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	public function enqueues() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin', 'WPForms\Admin\Settings\Captcha\Page::enqueues()' );

		( new Page() )->enqueues();
	}

	/**
	 * Use the CAPTCHA no-conflict mode.
	 *
	 * When enabled in the WPForms settings, forcefully remove all other
	 * CAPTCHA enqueues to prevent conflicts. Filter can be used to target
	 * specific pages, etc.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 */
	public function apply_noconflict() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin', 'WPForms\Admin\Settings\Captcha\Page::apply_noconflict()' );

		( new Page() )->apply_noconflict();
	}

	/**
	 * Check if CAPTCHA config is ready to display a preview.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 *
	 * @return bool
	 */
	protected function is_captcha_preview_ready() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin' );

		return (
			( 'hcaptcha' === $this->settings['provider'] || ( 'recaptcha' === $this->settings['provider'] && 'v2' === $this->settings['recaptcha_type'] ) ) &&
			! empty( $this->settings['site_key'] ) &&
			! empty( $this->settings['secret_key'] )
		);
	}

	/**
	 * Retrieve the CAPTCHA provider API URL.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 *
	 * @return string
	 */
	protected function get_api_url() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin' );

		$api_url = '';

		if ( $this->settings['provider'] === 'hcaptcha' ) {
			$api_url = self::HCAPTCHA_API_URL;
		}

		if ( $this->settings['provider'] === 'recaptcha' ) {
			$api_url = self::RECAPTCHA_API_URL;
		}

		if ( ! empty( $api_url ) ) {
			$api_url = add_query_arg( $this->get_api_url_query_arg(), $api_url );
		}

		return apply_filters( 'wpforms_admin_settings_captcha_get_api_url', $api_url, $this->settings );
	}

	/**
	 * Retrieve query arguments for the CAPTCHA API URL.
	 *
	 * @since      1.6.4
	 * @deprecated 1.8.0
	 *
	 * @return array
	 */
	protected function get_api_url_query_arg() {

		_deprecated_function( __METHOD__, '1.8.0 of the WPForms plugin' );

		return (array) apply_filters(
			'wpforms_admin_settings_captcha_get_api_url_query_arg', // phpcs:ignore WPForms.Comments.PHPDocHooks.RequiredHookDocumentation, WPForms.PHP.ValidateHooks.InvalidHookName
			[
				'onload' => 'wpformsSettingsCaptchaLoad',
				'render' => 'explicit',
			],
			$this->settings
		);
	}
}
