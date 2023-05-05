<?php

namespace WPForms\Admin\Settings\Captcha;

/**
 * Cloudflare Turnstile settings class.
 *
 * @since 1.8.0
 */
class Turnstile extends Captcha {

	/**
	 * Captcha variable used for JS invoking.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $api_var = 'turnstile';

	/**
	 * Captcha key name.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $slug = 'turnstile';

	/**
	 * The Turnstile Javascript URL-resource.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $url = 'https://challenges.cloudflare.com/turnstile/v0/api.js';

	/**
	 * Inline script for captcha initialization JS code.
	 *
	 * @since 1.8.0
	 *
	 * @return string
	 */
	protected function get_inline_script() {

		return /** @lang JavaScript */
			'const wpformsCaptcha = jQuery( ".wpforms-captcha" );
			if ( wpformsCaptcha.length > 0 ) { 
				var widgetID = ' . static::$api_var . '.render( ".wpforms-captcha", { 
					"refresh-expired": "never" 
				} ); 
				wpformsCaptcha.attr( "data-captcha-id", widgetID); 
				jQuery( document ).trigger( "wpformsSettingsCaptchaLoaded" ); 
			}';
	}

	/**
	 * Array of captcha settings fields.
	 *
	 * @since 1.8.0
	 *
	 * @return array[]
	 */
	public function get_settings_fields() {

		return [
			'turnstile-heading'    => [
				'id'       => 'turnstile-heading',
				'content'  => $this->get_field_desc(),
				'type'     => 'content',
				'no_label' => true,
				'class'    => [ 'section-heading' ],
			],
			'turnstile-site-key'   => [
				'id'   => 'turnstile-site-key',
				'name' => esc_html__( 'Site Key', 'wpforms-lite' ),
				'type' => 'text',
			],
			'turnstile-secret-key' => [
				'id'   => 'turnstile-secret-key',
				'name' => esc_html__( 'Secret Key', 'wpforms-lite' ),
				'type' => 'text',
			],
			'turnstile-fail-msg'   => [
				'id'      => 'turnstile-fail-msg',
				'name'    => esc_html__( 'Fail Message', 'wpforms-lite' ),
				'desc'    => esc_html__( 'Displays to users who fail the verification process.', 'wpforms-lite' ),
				'type'    => 'text',
				'default' => esc_html__( 'Cloudflare Turnstile verification failed, please try again later.', 'wpforms-lite' ),
			],
			'turnstile-theme'      => [
				'id'      => 'turnstile-theme',
				'name'    => esc_html__( 'Type', 'wpforms-lite' ),
				'type'    => 'select',
				'default' => 'auto',
				'options' => [
					'auto'  => esc_html__( 'Auto', 'wpforms-lite' ),
					'light' => esc_html__( 'Light', 'wpforms-lite' ),
					'dark'  => esc_html__( 'Dark', 'wpforms-lite' ),
				],
			],
		];
	}
}
