<?php

namespace WPForms\Frontend;

/**
 * AMP class.
 *
 * @since 1.8.1
 */
class Amp {

	/**
	 * Whether the current page is in AMP mode or not.
	 *
	 * @since 1.8.1
	 *
	 * @var bool
	 */
	private $is_amp_mode;

	/**
	 * Whether the current page is in AMP mode or not.
	 *
	 * @since 1.8.1
	 *
	 * @var Frontend
	 */
	private $frontend_obj;

	/**
	 * Constructor.
	 *
	 * @since 1.8.1
	 */
	public function __construct() {

		$this->frontend_obj = wpforms()->get( 'frontend' );

		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.8.1
	 */
	private function hooks() {

		add_filter( 'amp_skip_post', [ $this, 'skip_post' ] );
		add_filter( 'wpforms_frontend_form_atts', [ $this, 'form_atts' ], -PHP_INT_MAX, 2 );
		add_action( 'wpforms_frontend_output', [ $this, 'output_state' ], -PHP_INT_MAX, 5 );
	}

	/**
	 * Check whether the current page is in AMP mode or not.
	 *
	 * @since 1.8.1
	 *
	 * @return bool True if the current page is in AMP mode.
	 */
	public function is_amp() {

		if ( is_null( $this->is_amp_mode ) ) {
			$this->is_amp_mode = wpforms_is_amp();
		}

		return $this->is_amp_mode;
	}

	/**
	 * Stop AMP output.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data Form data and settings.
	 *
	 * @return bool True if we need to stop the output.
	 */
	public function stop_output( $form_data ) {

		// We need to stop output processing in case we are on AMP page.
		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
		if (
			wpforms_is_amp( false ) &&
			(
				! current_theme_supports( 'amp' ) ||
				/**
				 * Filters the pro status of the plugin.
				 *
				 * @since 1.5.4.2
				 *
				 * @param bool $pro Pro status.
				 */
				apply_filters( 'wpforms_amp_pro', wpforms()->is_pro() ) ||
				! is_ssl() ||
				! defined( 'AMP__VERSION' ) ||
				version_compare( AMP__VERSION, '1.2', '<' )
			)
		) {
			$form_id       = ! empty( $form_data['id'] ) ? (int) $form_data['id'] : 0;
			$full_page_url = home_url( add_query_arg( 'nonamp', '1' ) . '#wpforms-' . $form_id );

			/**
			 * Allow modifying the text or url for the full page on the AMP pages.
			 *
			 * @since 1.4.1.1
			 * @since 1.7.1 Added $form_id, $full_page_url, and $form_data arguments.
			 *
			 * @param string $text          Text.
			 * @param int    $form_id       Form id.
			 * @param string $full_page_url Full page url.
			 * @param array  $form_data     Form data and settings.
			 *
			 * @return string
			 */
			$text = (string) apply_filters(
				'wpforms_frontend_shortcode_amp_text',
				sprintf( /* translators: %s - URL to a non-amp version of a page with the form. */
					__( '<a href="%s">Go to the full page</a> to view and submit the form.', 'wpforms-lite' ),
					esc_url( $full_page_url )
				),
				$form_id,
				$full_page_url,
				$form_data
			);

			printf(
				'<p class="wpforms-shortcode-amp-text">%s</p>',
				wp_kses_post( $text )
			);

			return true;
		}
		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

		return false;
	}

	/**
	 * Disable AMP if query param is detected.
	 *
	 * This allows the full form to be accessible for Pro users or sites
	 * that do not have SSL.
	 *
	 * @since 1.8.1
	 *
	 * @param bool $skip Skip AMP mode, display full post.
	 *
	 * @return bool
	 */
	public function skip_post( $skip ) {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET['nonamp'] ) ? true : $skip;
	}

	/**
	 * Form attributes filter.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_atts Form attributes.
	 * @param array $form_data Form data.
	 *
	 * @return array
	 */
	public function form_atts( $form_atts, $form_data ) {

		if ( ! $this->is_amp() ) {
			return $form_atts;
		}

		// Set submitting state.
		if ( ! isset( $form_atts['atts']['on'] ) ) {
			$form_atts['atts']['on'] = '';
		} else {
			$form_atts['atts']['on'] .= ';';
		}

		$form_id = ! empty( $form_data['id'] ) ? (int) $form_data['id'] : 0;

		$form_atts['atts']['on'] .= sprintf(
			'submit:AMP.setState( %1$s ); submit-success:AMP.setState( %2$s ); submit-error:AMP.setState( %2$s );',
			wp_json_encode(
				[
					$this->get_form_amp_state_id( $form_id ) => [ 'submitting' => true ],
				]
			),
			wp_json_encode(
				[
					$this->get_form_amp_state_id( $form_id ) => [ 'submitting' => false ],
				]
			)
		);

		// Upgrade the form to be an amp-form to avoid sanitizer conversion.
		if ( isset( $form_atts['atts']['action'] ) ) {
			$form_atts['atts']['action-xhr'] = $form_atts['atts']['action'];
			$form_atts['atts']['verify-xhr'] = $form_atts['atts']['action-xhr'];

			unset( $form_atts['atts']['action'] );
		}

		return $form_atts;
	}

	/**
	 * Get the amp-state ID for a given form.
	 *
	 * @since 1.8.1
	 *
	 * @param int $form_id Form ID.
	 *
	 * @return string State ID.
	 */
	private function get_form_amp_state_id( $form_id ) {

		return sprintf( 'wpforms_form_state_%d', $form_id );
	}

	/**
	 * Output AMP state.
	 *
	 * @since 1.8.1
	 *
	 * @param array  $form_data   Form data and settings.
	 * @param null   $deprecated  Deprecated.
	 * @param string $title       Form title.
	 * @param string $description Form description.
	 * @param array  $errors      Errors.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function output_state( $form_data, $deprecated, $title, $description, $errors ) {

		if ( ! $this->is_amp() ) {
			return;
		}

		$state = [ 'submitting' => false ];

		$form_id = ! empty( $form_data['id'] ) ? (int) $form_data['id'] : 0;

		printf(
			'<amp-state id="%s"><script type="application/json">%s</script></amp-state>',
			$this->get_form_amp_state_id( $form_id ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			wp_json_encode( $state )
		);
	}

	/**
	 * Output submit success template.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data Form data and settings.
	 *
	 * @return bool True if the template was printed.
	 */
	public function output_success_template( $form_data ) {

		if ( ! $this->is_amp() ) {
			return false;
		}

		$this->frontend_obj->assets_confirmation( $form_data );

		$class = (int) wpforms_setting( 'disable-css', '1' ) === 1 ? 'wpforms-confirmation-container-full' : 'wpforms-confirmation-container';

		printf(
			'<div submit-success><template type="amp-mustache"><div class="%s {{#redirecting}}wpforms-redirection-message{{/redirecting}}">{{{message}}}</div></template></div>',
			esc_attr( $class )
		);

		return true;
	}

	/**
	 * Output submit error template.
	 *
	 * @since 1.8.1
	 *
	 * @return bool True if the template was printed.
	 */
	public function output_error_template() {

		if ( ! $this->is_amp() ) {
			return false;
		}

		echo '<div submit-error><template type="amp-mustache"><div class="wpforms-error-container"><p>{{{message}}}</p></div></template></div>';

		return true;
	}

	/**
	 * Get text attribute.
	 *
	 * @since 1.8.1
	 *
	 * @param int    $form_id  Form ID.
	 * @param array  $settings Form settings.
	 * @param string $submit   Submit button text.
	 *
	 * @return string
	 */
	public function get_text_attr( $form_id, $settings, $submit ) {

		return sprintf(
			'%s.submitting ? %s : %s',
			$this->get_form_amp_state_id( $form_id ),
			wp_json_encode( $settings['submit_text_processing'], JSON_UNESCAPED_UNICODE ),
			wp_json_encode( $submit, JSON_UNESCAPED_UNICODE )
		);
	}

	/**
	 * Output captcha.
	 *
	 * @since 1.8.1
	 *
	 * @param bool  $is_recaptcha_v3  Whether we use v3.
	 * @param array $captcha_settings Captcha settings.
	 * @param array $form_data        Form data.
	 *
	 * @return bool
	 */
	public function output_captcha( $is_recaptcha_v3, $captcha_settings, $form_data ) {

		if ( ! $this->is_amp() ) {
			return false;
		}

		if ( $is_recaptcha_v3 ) {

			printf(
				'<amp-recaptcha-input name="wpforms[recaptcha]" data-sitekey="%s" data-action="%s" layout="nodisplay"></amp-recaptcha-input>',
				esc_attr( $captcha_settings['site_key'] ),
				esc_attr( 'wpforms_' . $form_data['id'] )
			);

			return true;
		}

		if ( is_super_admin() ) {

			$captcha_provider = $captcha_settings['provider'] === 'hcaptcha' ? esc_html__( 'hCaptcha', 'wpforms-lite' ) : esc_html__( 'Google reCAPTCHA v2', 'wpforms-lite' );

			echo '<div class="wpforms-notice wpforms-warning" style="margin: 20px 0;">';
			printf(
				wp_kses( /* translators: %1$s - CAPTCHA provider name; %2$s - URL to reCAPTCHA documentation. */
					__( '%1$s is not supported by AMP and is currently disabled.<br><a href="%2$s" rel="noopener noreferrer" target="_blank">Upgrade to reCAPTCHA v3</a> for full AMP support. <br><em>Please note: this message is only displayed to site administrators.</em>', 'wpforms-lite' ),
					[
						'a'  => [
							'href'   => [],
							'rel'    => [],
							'target' => [],
						],
						'br' => [],
						'em' => [],
					]
				),
				$captcha_provider, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				'https://wpforms.com/docs/setup-captcha-wpforms/'
			);
			echo '</div>';

			return true;
		}

		return false;
	}
}
