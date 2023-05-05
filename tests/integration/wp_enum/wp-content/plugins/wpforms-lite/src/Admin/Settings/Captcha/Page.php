<?php

namespace WPForms\Admin\Settings\Captcha;

use WPForms\Admin\Notice;

/**
 * CAPTCHA setting page.
 *
 * @since 1.8.0
 */
class Page {

	/**
	 * Slug identifier for admin page view.
	 *
	 * @since 1.8.0
	 *
	 * @var string
	 */
	const VIEW = 'captcha';

	/**
	 * Saved CAPTCHA settings.
	 *
	 * @since 1.8.0
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * All available captcha types.
	 *
	 * @since 1.8.0
	 *
	 * @var array
	 */
	private $captchas;

	/**
	 * Initialize class.
	 *
	 * @since 1.8.0
	 */
	public function init() {

		// Only load if we are actually on the settings page.
		if ( ! wpforms_is_admin_page( 'settings' ) ) {
			return;
		}

		// Listen the previous reCAPTCHA page and safely redirect from it.
		if ( wpforms_is_admin_page( 'settings', 'recaptcha' ) ) {
			wp_safe_redirect( add_query_arg( 'view', self::VIEW, admin_url( 'admin.php?page=wpforms-settings' ) ) );
			exit;
		}

		$this->init_settings();
		$this->hooks();
	}

	/**
	 * Init CAPTCHA settings.
	 *
	 * @since 1.8.0
	 */
	public function init_settings() {

		$this->settings = wp_parse_args( wpforms_get_captcha_settings(), [ 'provider' => 'none' ] );

		/**
		 * Filter available captcha for the settings page.
		 *
		 * @since 1.8.0
		 *
		 * @param array $captcha  Array where key is captcha name and value is captcha class instance.
		 * @param array $settings Array of settings.
		 */
		$this->captchas = apply_filters(
			'wpforms_admin_settings_captcha_page_init_settings_available_captcha',
			[
				'hcaptcha'  => new HCaptcha(),
				'recaptcha' => new ReCaptcha(),
				'turnstile' => new Turnstile(),
			],
			$this->settings
		);

		foreach ( $this->captchas as $captcha ) {
			$captcha->init();
		}
	}

	/**
	 * Hooks.
	 *
	 * @since 1.8.0
	 */
	public function hooks() {

		add_filter( 'wpforms_settings_tabs', [ $this, 'register_settings_tabs' ], 5, 1 );
		add_filter( 'wpforms_settings_defaults', [ $this, 'register_settings_fields' ], 5, 1 );
		add_action( 'wpforms_settings_updated', [ $this, 'updated' ] );
		add_action( 'wpforms_settings_enqueue', [ $this, 'enqueues' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'apply_noconflict' ], 9999 );
	}

	/**
	 * Register CAPTCHA settings tab.
	 *
	 * @since 1.8.0
	 *
	 * @param array $tabs Admin area tabs list.
	 *
	 * @return array
	 */
	public function register_settings_tabs( $tabs ) {

		$captcha = [
			self::VIEW => [
				'name'   => esc_html__( 'CAPTCHA', 'wpforms-lite' ),
				'form'   => true,
				'submit' => esc_html__( 'Save Settings', 'wpforms-lite' ),
			],
		];

		return wpforms_array_insert( $tabs, $captcha, 'email' );
	}

	/**
	 * Register CAPTCHA settings fields.
	 *
	 * @since 1.8.0
	 *
	 * @param array $settings Admin area settings list.
	 *
	 * @return array
	 */
	public function register_settings_fields( $settings ) {

		$settings[ self::VIEW ] = [
			self::VIEW . '-heading'  => [
				'id'       => self::VIEW . '-heading',
				'content'  => '<h4>' . esc_html__( 'CAPTCHA', 'wpforms-lite' ) . '</h4><p>' . esc_html__( 'A CAPTCHA is an anti-spam technique which helps to protect your website from spam and abuse while letting real people pass through with ease. WPForms supports two popular services.', 'wpforms-lite' ) . '</p>',
				'type'     => 'content',
				'no_label' => true,
				'class'    => [ 'wpforms-setting-captcha-heading', 'section-heading' ],
			],
			self::VIEW . '-provider' => [
				'id'      => self::VIEW . '-provider',
				'type'    => 'radio',
				'default' => 'none',
				'options' => [
					'hcaptcha'  => 'hCaptcha',
					'recaptcha' => 'reCAPTCHA',
					'turnstile' => 'Turnstile',
					'none'      => esc_html__( 'None', 'wpforms-lite' ),
				],
				'desc'    => sprintf(
					wp_kses( /* translators: %s - WPForms.com CAPTCHA comparison page URL. */
						__( 'Not sure which service is right for you? <a href="%s" target="_blank" rel="noopener noreferrer">Check out our comparison</a> for more details.', 'wpforms-lite' ),
						[
							'a' => [
								'href'   => [],
								'target' => [],
								'rel'    => [],
							],
						]
					),
					esc_url( wpforms_utm_link( 'https://wpforms.com/docs/setup-captcha-wpforms/', 'Settings - Captcha', 'Captcha Comparison Documentation' ) )
				),
			],
		];

		// Add settings fields for each of available captcha types.
		foreach ( $this->captchas as $captcha ) {
			$settings[ self::VIEW ] = array_merge( $settings[ self::VIEW ], $captcha->get_settings_fields() );
		}

		$settings[ self::VIEW ] = array_merge(
			$settings[ self::VIEW ],
			[
				self::VIEW . '-preview' =>
					[
						'id'      => self::VIEW . '-preview',
						'name'    => esc_html__( 'Preview', 'wpforms-lite' ),
						'content' => '<p class="desc">' . esc_html__( 'Please save settings to generate a preview of your CAPTCHA here.', 'wpforms-lite' ) . '</p>',
						'type'    => 'content',
						'class'   => [ 'wpforms-hidden' ],
					],
				'recaptcha-noconflict'  => [
					'id'   => 'recaptcha-noconflict',
					'name' => esc_html__( 'No-Conflict Mode', 'wpforms-lite' ),
					'desc' => esc_html__( 'Check this option to forcefully remove other CAPTCHA occurrences in order to prevent conflicts. Only enable this option if your site is having compatibility issues or instructed by support.', 'wpforms-lite' ),
					'type' => 'checkbox',
				],
			]
		);

		if (
			$this->settings['provider'] === 'hcaptcha' ||
			$this->settings['provider'] === 'turnstile' ||
			( $this->settings['provider'] === 'recaptcha' && $this->settings['recaptcha_type'] === 'v2' )
		) {

			// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName

			/**
			 * Modify captcha settings data.
			 *
			 * @since 1.6.4
			 *
			 * @param array $data Array of settings.
			 */
			$data = apply_filters(
				'wpforms_admin_pages_settings_captcha_data',
				[
					'sitekey' => $this->settings['site_key'],
					'theme'   => $this->settings['theme'],
				]
			);
			// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

			// Prepare HTML for CAPTCHA preview.
			$placeholder_description = $settings[ self::VIEW ][ self::VIEW . '-preview' ]['content'];
			$captcha_description     = esc_html__( 'This CAPTCHA is generated using your site and secret keys. If an error is displayed, please double-check your keys.', 'wpforms-lite' );
			$captcha_preview         = sprintf(
				'<div class="wpforms-captcha-container" style="pointer-events:none!important;cursor:default!important;">
					<div %s></div>
					<input type="text" name="wpforms-captcha-hidden" class="wpforms-recaptcha-hidden" style="position:absolute!important;clip:rect(0,0,0,0)!important;height:1px!important;width:1px!important;border:0!important;overflow:hidden!important;padding:0!important;margin:0!important;">
				</div>',
				wpforms_html_attributes( '', [ 'wpforms-captcha', 'wpforms-captcha-' . $this->settings['provider'] ], $data )
			);

			$settings[ self::VIEW ][ self::VIEW . '-preview' ]['content'] = sprintf(
				'<div class="wpforms-captcha-preview">
					%1$s <p class="desc">%2$s</p>
				</div>
				<div class="wpforms-captcha-placeholder wpforms-hidden">%3$s</div>',
				$captcha_preview,
				$captcha_description,
				$placeholder_description
			);
			$settings[ self::VIEW ][ self::VIEW . '-preview' ]['class']   = [];
		}

		return $settings;
	}

	/**
	 * Re-init CAPTCHA settings when plugin settings were updated.
	 *
	 * @since 1.8.0
	 */
	public function updated() {

		$this->init_settings();
		$this->notice();
	}

	/**
	 * Display notice about the CAPTCHA preview.
	 *
	 * @since 1.8.0
	 */
	private function notice() {

		if ( ! wpforms_is_admin_page( 'settings', self::VIEW ) || ! $this->is_captcha_preview_ready() ) {
			return;
		}

		Notice::info( esc_html__( 'A preview of your CAPTCHA is displayed below. Please view to verify the CAPTCHA settings are correct.', 'wpforms-lite' ) );
	}

	/**
	 * Check if CAPTCHA config is ready to display a preview.
	 *
	 * @since 1.8.0
	 *
	 * @return bool
	 */
	private function is_captcha_preview_ready() {

		$current_captcha = $this->get_current_captcha();

		if ( ! $current_captcha ) {
			return false;
		}

		return $current_captcha->is_captcha_preview_ready();
	}

	/**
	 * Enqueue assets for the CAPTCHA settings page.
	 *
	 * @since 1.8.0
	 */
	public function enqueues() {

		$current_captcha = $this->get_current_captcha();

		if ( ! $current_captcha ) {
			return;
		}

		$current_captcha->enqueues();
	}

	/**
	 * Get current active captcha object.
	 *
	 * @since 1.8.0
	 *
	 * @return object|string
	 */
	private function get_current_captcha() {

		return ! empty( $this->captchas[ $this->settings['provider'] ] ) ? $this->captchas[ $this->settings['provider'] ] : '';
	}

	/**
	 * Use the CAPTCHA no-conflict mode.
	 *
	 * When enabled in the WPForms settings, forcefully remove all other
	 * CAPTCHA enqueues to prevent conflicts. Filter can be used to target
	 * specific pages, etc.
	 *
	 * @since 1.6.4
	 */
	public function apply_noconflict() {

		if (
			! wpforms_is_admin_page( 'settings', self::VIEW ) ||
			empty( wpforms_setting( 'recaptcha-noconflict' ) ) ||

			/**
			 * Allow/disallow applying non-conflict mode for captcha scripts.
			 *
			 * @since 1.6.4
			 *
			 * @param boolean $allow True/false. Default: true.
			 */
			! apply_filters( 'wpforms_admin_settings_captcha_apply_noconflict', true ) // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
		) {
			return;
		}

		$scripts = wp_scripts();
		$urls    = [ 'google.com/recaptcha', 'gstatic.com/recaptcha', 'hcaptcha.com/1', 'challenges.cloudflare.com/turnstile' ];

		foreach ( $scripts->queue as $handle ) {

			// Skip the WPForms JavaScript assets.
			if (
				! isset( $scripts->registered[ $handle ] ) ||
				false !== strpos( $scripts->registered[ $handle ]->handle, 'wpforms' )
			) {
				return;
			}

			foreach ( $urls as $url ) {
				if ( false !== strpos( $scripts->registered[ $handle ]->src, $url ) ) {
					wp_dequeue_script( $handle );
					wp_deregister_script( $handle );
					break;
				}
			}
		}
	}
}
