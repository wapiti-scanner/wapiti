<?php

namespace WPForms\Admin\Education\Builder;

use \WPForms\Admin\Education\EducationInterface;

/**
 * Builder/ReCaptcha Education feature.
 *
 * @since 1.6.6
 */
class Captcha implements EducationInterface {

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.6
	 */
	public function allow_load() {

		return wp_doing_ajax();
	}

	/**
	 * Init.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		// Define hooks.
		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_action( 'wp_ajax_wpforms_update_field_captcha', [ $this, 'captcha_field_callback' ] );
	}

	/**
	 * Targeting on hCaptcha/reCAPTCHA field button in the builder.
	 *
	 * @since 1.6.6
	 */
	public function captcha_field_callback() {

		// Run a security check.
		check_ajax_referer( 'wpforms-builder', 'nonce' );

		// Check for form ID.
		if ( empty( $_POST['id'] ) ) {
			wp_send_json_error( esc_html__( 'No form ID found.', 'wpforms-lite' ) );
		}

		$form_id = absint( $_POST['id'] );

		// Check for permissions.
		if ( ! wpforms_current_user_can( 'edit_form_single', $form_id ) ) {
			wp_send_json_error( esc_html__( 'You do not have permission.', 'wpforms-lite' ) );
		}

		// Get an actual form data.
		$form_data = wpforms()->get( 'form' )->get( $form_id, [ 'content_only' => true ] );

		// Check that CAPTCHA is configured in the settings.
		$captcha_settings = wpforms_get_captcha_settings();
		$captcha_name     = $this->get_captcha_name( $captcha_settings );

		if ( empty( $form_data ) || empty( $captcha_name ) ) {
			wp_send_json_error( esc_html__( 'Something wrong. Please try again later.', 'wpforms-lite' ) );
		}

		// Prepare a result array.
		$data = $this->get_captcha_result_mockup( $captcha_settings );

		if ( empty( $captcha_settings['site_key'] ) || empty( $captcha_settings['secret_key'] ) ) {

			// If CAPTCHA is not configured in the WPForms plugin settings.
			$data['current'] = 'not_configured';

		} elseif ( ! isset( $form_data['settings']['recaptcha'] ) || $form_data['settings']['recaptcha'] !== '1' ) {

			// If CAPTCHA is configured in WPForms plugin settings, but wasn't set in form settings.
			$data['current'] = 'configured_not_enabled';

		} else {

			// If CAPTCHA is configured in WPForms plugin and form settings.
			$data['current'] = 'configured_enabled';
		}

		wp_send_json_success( $data );
	}

	/**
	 * Retrieve the CAPTCHA name.
	 *
	 * @since 1.6.6
	 *
	 * @param array $settings The CAPTCHA settings.
	 *
	 * @return string
	 */
	private function get_captcha_name( $settings ) {

		if ( empty( $settings['provider'] ) ) {
			return '';
		}

		if ( empty( $settings['site_key'] ) && empty( $settings['secret_key'] ) ) {
			return esc_html__( 'CAPTCHA', 'wpforms-lite' );
		}

		if ( $settings['provider'] === 'hcaptcha' ) {
			return esc_html__( 'hCaptcha', 'wpforms-lite' );
		}

		if ( $settings['provider'] === 'turnstile' ) {
			return esc_html__( 'Cloudflare Turnstile', 'wpforms-lite' );
		}

		$recaptcha_names = [
			'v2'        => esc_html__( 'Google Checkbox v2 reCAPTCHA', 'wpforms-lite' ),
			'invisible' => esc_html__( 'Google Invisible v2 reCAPTCHA', 'wpforms-lite' ),
			'v3'        => esc_html__( 'Google v3 reCAPTCHA', 'wpforms-lite' ),
		];

		return isset( $recaptcha_names[ $settings['recaptcha_type'] ] ) ? $recaptcha_names[ $settings['recaptcha_type'] ] : '';
	}

	/**
	 * Get CAPTCHA callback result mockup.
	 *
	 * @since 1.6.6
	 *
	 * @param array $settings The CAPTCHA settings.
	 *
	 * @return array
	 */
	private function get_captcha_result_mockup( $settings ) {

		$captcha_name = $this->get_captcha_name( $settings );

		if ( empty( $captcha_name ) ) {
			wp_send_json_error( esc_html__( 'Something wrong. Please, try again later.', 'wpforms-lite' ) );
		}

		return [
			'current'  => false,
			'cases'    => [
				'not_configured'         => [
					'title'   => esc_html__( 'Heads up!', 'wpforms-lite' ),
					'content' => sprintf(
						wp_kses( /* translators: %1$s - CAPTCHA settings page URL; %2$s - WPForms.com doc URL; %3$s - CAPTCHA name. */
							__( 'The %3$s settings have not been configured yet. Please complete the setup in your <a href="%1$s" target="_blank">WPForms Settings</a>, and check out our <a href="%2$s" target="_blank" rel="noopener noreferrer">step by step tutorial</a> for full details.', 'wpforms-lite' ),
							[
								'a' => [
									'href'   => true,
									'rel'    => true,
									'target' => true,
								],
							]
						),
						esc_url( admin_url( 'admin.php?page=wpforms-settings&view=captcha' ) ),
						esc_url( wpforms_utm_link( 'https://wpforms.com/docs/setup-captcha-wpforms/', 'builder-modal', 'Captcha Documentation' ) ),
						$captcha_name
					),
				],
				'configured_not_enabled' => [
					'title'   => false,
					/* translators: %s - CAPTCHA name. */
					'content' => sprintf( esc_html__( '%s has been enabled for this form. Don\'t forget to save your form!', 'wpforms-lite' ), $captcha_name ),
				],
				'configured_enabled'     => [
					'title'   => false,
					/* translators: %s - CAPTCHA name. */
					'content' => sprintf( esc_html__( 'Are you sure you want to disable %s for this form?', 'wpforms-lite' ), $captcha_name ),
					'cancel'  => true,
				],
			],
			'provider' => $settings['provider'],
		];
	}
}
