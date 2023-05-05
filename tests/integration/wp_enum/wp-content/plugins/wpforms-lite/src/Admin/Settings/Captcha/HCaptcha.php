<?php

namespace WPForms\Admin\Settings\Captcha;

/**
 * HCaptcha settings class.
 *
 * @since 1.8.0
 */
class HCaptcha extends Captcha {

	/**
	 * Captcha variable used for JS invoking.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $api_var = 'hcaptcha';

	/**
	 * Get captcha key name.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $slug = 'hcaptcha';

	/**
	 * The hCaptcha Javascript URL-resource.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	protected static $url = 'https://hcaptcha.com/1/api.js';

	/**
	 * Array of captcha settings fields.
	 *
	 * @since 1.8.0
	 *
	 * @return array[]
	 */
	public function get_settings_fields() {

		return [
			'hcaptcha-heading'    => [
				'id'       => 'hcaptcha-heading',
				'content'  => $this->get_field_desc(),
				'type'     => 'content',
				'no_label' => true,
				'class'    => [ 'section-heading' ],
			],
			'hcaptcha-site-key'   => [
				'id'   => 'hcaptcha-site-key',
				'name' => esc_html__( 'Site Key', 'wpforms-lite' ),
				'type' => 'text',
			],
			'hcaptcha-secret-key' => [
				'id'   => 'hcaptcha-secret-key',
				'name' => esc_html__( 'Secret Key', 'wpforms-lite' ),
				'type' => 'text',
			],
			'hcaptcha-fail-msg'   => [
				'id'      => 'hcaptcha-fail-msg',
				'name'    => esc_html__( 'Fail Message', 'wpforms-lite' ),
				'desc'    => esc_html__( 'Displays to users who fail the verification process.', 'wpforms-lite' ),
				'type'    => 'text',
				'default' => esc_html__( 'hCaptcha verification failed, please try again later.', 'wpforms-lite' ),
			],
		];
	}
}
