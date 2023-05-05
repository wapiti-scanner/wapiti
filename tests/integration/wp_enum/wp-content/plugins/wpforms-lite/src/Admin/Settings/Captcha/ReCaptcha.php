<?php

namespace WPForms\Admin\Settings\Captcha;

/**
 * ReCaptcha settings class.
 *
 * @since 1.8.0
 */
class ReCaptcha extends Captcha {

	/**
	 * Captcha variable used for JS invoking.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $api_var = 'grecaptcha';

	/**
	 * Get captcha key name.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $slug = 'recaptcha';

	/**
	 * The ReCAPTCHA Javascript URL-resource.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $url = 'https://www.google.com/recaptcha/api.js';

	/**
	 * Array of captcha settings fields.
	 *
	 * @since 1.8.0
	 *
	 * @return array[]
	 */
	public function get_settings_fields() {

		return [
			'recaptcha-heading'      => [
				'id'       => 'recaptcha-heading',
				'content'  => $this->get_field_desc(),
				'type'     => 'content',
				'no_label' => true,
				'class'    => [ 'wpforms-setting-recaptcha', 'section-heading' ],
			],
			'recaptcha-type'         => [
				'id'      => 'recaptcha-type',
				'name'    => esc_html__( 'Type', 'wpforms-lite' ),
				'type'    => 'radio',
				'default' => 'v2',
				'options' => [
					'v2'        => esc_html__( 'Checkbox reCAPTCHA v2', 'wpforms-lite' ),
					'invisible' => esc_html__( 'Invisible reCAPTCHA v2', 'wpforms-lite' ),
					'v3'        => esc_html__( 'reCAPTCHA v3', 'wpforms-lite' ),
				],
				'class'   => [ 'wpforms-setting-recaptcha' ],
			],
			'recaptcha-site-key'     => [
				'id'   => 'recaptcha-site-key',
				'name' => esc_html__( 'Site Key', 'wpforms-lite' ),
				'type' => 'text',
			],
			'recaptcha-secret-key'   => [
				'id'   => 'recaptcha-secret-key',
				'name' => esc_html__( 'Secret Key', 'wpforms-lite' ),
				'type' => 'text',
			],
			'recaptcha-fail-msg'     => [
				'id'      => 'recaptcha-fail-msg',
				'name'    => esc_html__( 'Fail Message', 'wpforms-lite' ),
				'desc'    => esc_html__( 'Displays to users who fail the verification process.', 'wpforms-lite' ),
				'type'    => 'text',
				'default' => esc_html__( 'Google reCAPTCHA verification failed, please try again later.', 'wpforms-lite' ),
			],
			'recaptcha-v3-threshold' => [
				'id'      => 'recaptcha-v3-threshold',
				'name'    => esc_html__( 'Score Threshold', 'wpforms-lite' ),
				'desc'    => esc_html__( 'reCAPTCHA v3 returns a score (1.0 is very likely a good interaction, 0.0 is very likely a bot). If the score less than or equal to this threshold, the form submission will be blocked and the message above will be displayed.', 'wpforms-lite' ),
				'type'    => 'number',
				'attr'    => [
					'step' => '0.1',
					'min'  => '0.0',
					'max'  => '1.0',
				],
				'default' => esc_html__( '0.4', 'wpforms-lite' ),
				'class'   => $this->settings['provider'] === 'recaptcha' && $this->settings['recaptcha_type'] === 'v3' ? [ 'wpforms-setting-recaptcha' ] : [ 'wpforms-setting-recaptcha', 'wpforms-hidden' ],
			],
		];
	}
}
