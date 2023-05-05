<?php

namespace WPForms\Admin\Builder;

use WPForms\Forms\Akismet;
use WPForms_Builder_Panel_Settings;

/**
 * AntiSpam class.
 *
 * @since 1.7.8
 */
class AntiSpam {

	/**
	 * Form data and settings.
	 *
	 * @since 1.7.8
	 *
	 * @var array
	 */
	private $form_data;

	/**
	 * Init class.
	 *
	 * @since 1.7.8
	 */
	public function init() {

		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.7.8
	 */
	protected function hooks() {

		add_action( 'wpforms_form_settings_panel_content', [ $this, 'panel_content' ], 10, 2 );
	}

	/**
	 * Add a content for `Spam Protection and Security` panel.
	 *
	 * @since 1.7.8
	 *
	 * @param WPForms_Builder_Panel_Settings $instance Settings panel instance.
	 */
	public function panel_content( $instance ) {

		$this->form_data = $instance->form_data;

		echo '<div class="wpforms-panel-content-section wpforms-panel-content-section-anti_spam">';
		echo '<div class="wpforms-panel-content-section-title">';
		esc_html_e( 'Spam Protection and Security', 'wpforms-lite' );
		echo '</div>';

		$antispam = wpforms_panel_field(
			'toggle',
			'settings',
			'antispam',
			$this->form_data,
			__( 'Enable anti-spam protection', 'wpforms-lite' ),
			[
				'tooltip' => __( 'Turn on invisible spam protection.', 'wpforms-lite' ),
			],
			false
		);

		wpforms_panel_fields_group(
			$antispam,
			[
				'description' => __( 'Behind-the-scenes spam filtering that\'s invisible to your visitors.', 'wpforms-lite' ),
				'title'       => __( 'Protection', 'wpforms-lite' ),
			]
		);

		if ( ! empty( $this->form_data['settings']['honeypot'] ) ) {
			wpforms_panel_field(
				'toggle',
				'settings',
				'honeypot',
				$this->form_data,
				__( 'Enable anti-spam honeypot', 'wpforms-lite' )
			);
		}

		$this->akismet_settings();
		$this->captcha_settings();

		/**
		 * Fires once in the end of content panel before Also Available section.
		 *
		 * @since 1.7.8
		 *
		 * @param array $form_data Form data and settings.
		 */
		do_action( 'wpforms_admin_builder_anti_spam_panel_content', $this->form_data );

		wpforms_panel_fields_group(
			$this->get_also_available_block(),
			[
				'unfoldable' => true,
				'default'    => 'opened',
				'group'      => 'also_available',
				'title'      => __( 'Also Available', 'wpforms-lite' ),
				'borders'    => [ 'top' ],
			]
		);

		echo '</div>';
	}

	/**
	 * Output the *CAPTCHA settings.
	 *
	 * @since 1.7.8
	 */
	private function captcha_settings() {

		$captcha_settings = wpforms_get_captcha_settings();

		if (
			empty( $captcha_settings['provider'] ) ||
			$captcha_settings['provider'] === 'none' ||
			empty( $captcha_settings['site_key'] ) ||
			empty( $captcha_settings['secret_key'] )
		) {
			return;
		}

		$captcha_types = [
			'hcaptcha'  => __( 'Enable hCaptcha', 'wpforms-lite' ),
			'turnstile' => __( 'Enable Cloudflare Turnstile', 'wpforms-lite' ),
			'recaptcha' => [
				'v2'        => __( 'Enable Google Checkbox v2 reCAPTCHA', 'wpforms-lite' ),
				'invisible' => __( 'Enable Google Invisible v2 reCAPTCHA', 'wpforms-lite' ),
				'v3'        => __( 'Enable Google v3 reCAPTCHA', 'wpforms-lite' ),
			],
		];

		$is_recaptcha  = $captcha_settings['provider'] === 'recaptcha';
		$captcha_types = $is_recaptcha ? $captcha_types['recaptcha'] : $captcha_types;
		$captcha_key   = $is_recaptcha ? $captcha_settings['recaptcha_type'] : $captcha_settings['provider'];
		$label         = ! empty( $captcha_types[ $captcha_key ] ) ? $captcha_types[ $captcha_key ] : '';

		$recaptcha = wpforms_panel_field(
			'toggle',
			'settings',
			'recaptcha',
			$this->form_data,
			$label,
			[
				'data'    => [
					'provider' => $captcha_settings['provider'],
				],
				'tooltip' => __( 'Enable third-party CAPTCHAs to prevent form submissions from bots.', 'wpforms-lite' ),
			],
			false
		);

		wpforms_panel_fields_group(
			$recaptcha,
			[
				'description' => __( 'Automated tests that help to prevent bots from submitting your forms.', 'wpforms-lite' ),
				'title'       => __( 'CAPTCHA', 'wpforms-lite' ),
				'borders'     => [ 'top' ],
			]
		);
	}

	/**
	 * Output the Akismet settings.
	 *
	 * @since 1.7.8
	 */
	private function akismet_settings() {

		if ( ! Akismet::is_installed() ) {
			return;
		}

		$args = [];

		if ( ! Akismet::is_configured() ) {
			$args['data']['akismet-status'] = 'akismet_no_api_key';
		}

		if ( ! Akismet::is_activated() ) {
			$args['data']['akismet-status'] = 'akismet_not_activated';
		}

		// If Akismet isn't available, disable the Akismet toggle.
		if ( isset( $args['data'] ) ) {
			$args['input_class'] = 'wpforms-akismet-disabled';
			$args['value']       = '0';
		}

		wpforms_panel_field(
			'toggle',
			'settings',
			'akismet',
			$this->form_data,
			__( 'Enable Akismet anti-spam protection', 'wpforms-lite' ),
			$args
		);
	}

	/**
	 * Get the Also Available block.
	 *
	 * @since 1.7.8
	 *
	 * @return string
	 */
	private function get_also_available_block() {

		$get_started_button_text = __( 'Get Started &rarr;', 'wpforms-lite' );
		$upgrade_to_pro_text     = __( 'Upgrade to Pro', 'wpforms-lite' );
		$captcha_settings        = wpforms_get_captcha_settings();
		$upgrade_url             = 'https://wpforms.com/lite-upgrade/';
		$utm_medium              = 'Builder Settings';

		$blocks = [
			'country_filter' => [
				'logo'        => WPFORMS_PLUGIN_URL . 'assets/images/anti-spam/country-filter.svg',
				'title'       => __( 'Country Filter', 'wpforms-lite' ),
				'description' => __( 'Stop spam at its source. Allow or deny entries from specific countries.', 'wpforms-lite' ),
				'link'        => wpforms_utm_link( $upgrade_url, $utm_medium, 'Country Filter Feature' ),
				'link_text'   => $upgrade_to_pro_text,
				'class'       => 'wpforms-panel-content-also-available-item-upgrade-to-pro',
				'show'        => ! wpforms()->is_pro(),
			],
			'keyword_filter' => [
				'logo'        => WPFORMS_PLUGIN_URL . 'assets/images/anti-spam/keyword-filter.svg',
				'title'       => __( 'Keyword Filter', 'wpforms-lite' ),
				'description' => __( 'Block form entries that contain specific words or phrases that you define.', 'wpforms-lite' ),
				'link'        => wpforms_utm_link( $upgrade_url, $utm_medium, 'Keyword Filter Feature' ),
				'link_text'   => $upgrade_to_pro_text,
				'class'       => 'wpforms-panel-content-also-available-item-upgrade-to-pro',
				'show'        => ! wpforms()->is_pro(),
			],
			'custom_captcha' => [
				'logo'        => WPFORMS_PLUGIN_URL . 'assets/images/anti-spam/custom-captcha.svg',
				'title'       => __( 'Custom Captcha', 'wpforms-lite' ),
				'description' => __( 'Ask custom questions or require your visitor to answer a random math puzzle.', 'wpforms-lite' ),
				'link'        => wpforms()->is_pro() ? '#' : wpforms_utm_link( $upgrade_url, $utm_medium, 'Custom Captcha Addon' ),
				'link_text'   => wpforms()->is_pro() ? __( 'Add to Form', 'wpforms-lite' ) : $upgrade_to_pro_text,
				'class'       => wpforms()->is_pro() ? 'wpforms-panel-content-also-available-item-add-captcha' : 'wpforms-panel-content-also-available-item-upgrade-to-pro',
				'show'        => true,
			],
			'reCAPTCHA'      => [
				'logo'        => WPFORMS_PLUGIN_URL . 'assets/images/anti-spam/recaptcha.svg',
				'title'       => 'reCAPTCHA',
				'description' => __( 'Add Google\'s free anti-spam service and choose between visible or invisible CAPTCHAs.','wpforms-lite' ),
				'link'        => wpforms_utm_link( 'https://wpforms.com/docs/how-to-set-up-and-use-recaptcha-in-wpforms/', $utm_medium, 'reCAPTCHA Feature' ),
				'link_text'   => $get_started_button_text,
				'show'        => $captcha_settings['provider'] !== 'recaptcha' || empty( wpforms_setting( 'captcha-provider' ) ),
			],
			'hCaptcha'       => [
				'logo'        => WPFORMS_PLUGIN_URL . 'assets/images/anti-spam/hcaptcha.svg',
				'title'       => 'hCaptcha',
				'description' => __( 'Turn on free, privacy-oriented spam prevention that displays a visual CAPTCHA.','wpforms-lite' ),
				'link'        => wpforms_utm_link( 'https://wpforms.com/docs/how-to-set-up-and-use-hcaptcha-in-wpforms/', $utm_medium, 'hCaptcha Feature' ),
				'link_text'   => $get_started_button_text,
				'show'        => $captcha_settings['provider'] !== 'hcaptcha',
			],
			'turnstile'      => [
				'logo'        => WPFORMS_PLUGIN_URL . 'assets/images/anti-spam/cloudflare.svg',
				'title'       => 'Cloudflare Turnstile',
				'description' => __( 'Enable free, CAPTCHA-like spam protection that protects data privacy.','wpforms-lite' ),
				'link'        => wpforms_utm_link( 'https://wpforms.com/docs/setting-up-cloudflare-turnstile/', $utm_medium, 'Cloudflare Turnstile Feature' ),
				'link_text'   => $get_started_button_text,
				'show'        => $captcha_settings['provider'] !== 'turnstile',
			],
			'akismet'        => [
				'logo'        => WPFORMS_PLUGIN_URL . 'assets/images/anti-spam/akismet.svg',
				'title'       => 'Akismet',
				'description' => __( 'Integrate the powerful spam-fighting service trusted by millions of sites.','wpforms-lite' ),
				'link'        => wpforms_utm_link( 'https://wpforms.com/docs/setting-up-akismet-anti-spam-protection/', $utm_medium, 'Akismet Feature' ),
				'link_text'   => $get_started_button_text,
				'show'        => ! Akismet::is_installed(),
			],
		];

		return wpforms_render(
			'builder/antispam/also-available',
			[ 'blocks' => $blocks ],
			true
		);
	}
}
