<?php

namespace WPForms\Admin\Settings\Captcha;

/**
 * Base captcha settings class.
 *
 * @since 1.8.0
 */
abstract class Captcha {

	/**
	 * Saved CAPTCHA settings.
	 *
	 * @since 1.8.0
	 *
	 * @var array
	 */
	protected $settings;

	/**
	 * List of required static properties.
	 *
	 * @since 1.8.0
	 *
	 * @var array
	 */
	private $required_static_properties = [
		'api_var',
		'slug',
		'url',
	];

	/**
	 * Initialize class.
	 *
	 * @since 1.8.0
	 */
	public function init() {

		$this->settings = wp_parse_args( wpforms_get_captcha_settings(), [ 'provider' => 'none' ] );

		foreach ( $this->required_static_properties as $property ) {
			if ( empty( static::${$property} ) ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
				trigger_error(
					sprintf(
						'The $%s static property is required for a %s class',
						esc_html( $property ),
						__CLASS__
					),
					E_USER_ERROR
				);
			}
		}
	}

	/**
	 * Array of captcha settings fields.
	 *
	 * @since 1.8.0
	 *
	 * @return array[]
	 */
	abstract public function get_settings_fields();

	/**
	 * Get API request url for the captcha preview.
	 *
	 * @since 1.8.0
	 *
	 * @return string
	 */
	public function get_api_url() {

		$url = static::$url;

		if ( ! empty( $url ) ) {
			$url = add_query_arg( $this->get_api_url_query_arg(), $url );
		}

		/**
		 * Filter API URL.
		 *
		 * @since 1.6.4
		 *
		 * @param string $url      API URL.
		 * @param array  $settings Captcha settings array.
		 */
		return apply_filters( 'wpforms_admin_settings_captcha_get_api_url', $url, $this->settings );
	}

	/**
	 * Enqueue assets for the CAPTCHA settings page.
	 *
	 * @since 1.8.0
	 */
	public function enqueues() {

		/**
		 * Allow/disallow to enquire captcha settings.
		 *
		 * @since 1.6.4
		 *
		 * @param boolean $allow True/false. Default: false.
		 */
		$disable_enqueues = apply_filters( 'wpforms_admin_settings_captcha_enqueues_disable', false );

		if ( $disable_enqueues || ! $this->is_captcha_preview_ready() ) {
			return;
		}

		$api_url       = $this->get_api_url();
		$provider_name = $this->settings['provider'];
		$handle        = "wpforms-settings-{$provider_name}";

		wp_enqueue_script( $handle, $api_url, [ 'jquery' ], null, true );
		wp_add_inline_script( $handle, $this->get_inline_script() );
	}

	/**
	 * Inline script for initialize captcha JS code.
	 *
	 * @since 1.8.0
	 *
	 * @return string
	 */
	protected function get_inline_script() {

		return /** @lang JavaScript */
			'var wpformsSettingsCaptchaLoad = function() {
				jQuery( ".wpforms-captcha" ).each( function( index, el ) {
					var widgetID = ' . static::$api_var . '.render( el );
					jQuery( el ).attr( "data-captcha-id", widgetID );
				} );
				jQuery( document ).trigger( "wpformsSettingsCaptchaLoaded" );
		};';
	}

	/**
	 * Check if CAPTCHA config is ready to display a preview.
	 *
	 * @since 1.8.0
	 *
	 * @return bool
	 */
	public function is_captcha_preview_ready() {

		return (
			( $this->settings['provider'] === static::$slug || ( $this->settings['provider'] === 'recaptcha' && $this->settings['recaptcha_type'] === 'v2' ) ) &&
			! empty( $this->settings['site_key'] ) &&
			! empty( $this->settings['secret_key'] )
		);
	}

	/**
	 * Retrieve query arguments for the CAPTCHA API URL.
	 *
	 * @since 1.8.0
	 *
	 * @return array
	 */
	protected function get_api_url_query_arg() {

		/**
		 * Modify captcha api url parameters.
		 *
		 * @since 1.8.0
		 *
		 * @param array $params Array of parameters.
		 * @param array $params Saved CAPTCHA settings.
		 */
		return (array) apply_filters(
			'wpforms_admin_settings_captcha_get_api_url_query_arg',
			[
				'onload' => 'wpformsSettingsCaptchaLoad',
				'render' => 'explicit',
			],
			$this->settings
		);
	}

	/**
	 * Heading description.
	 *
	 * @since 1.8.0
	 *
	 * @return string
	 */
	public function get_field_desc() {

		return wpforms_render( 'admin/settings/' . static::$slug . '-description' );
	}
}
