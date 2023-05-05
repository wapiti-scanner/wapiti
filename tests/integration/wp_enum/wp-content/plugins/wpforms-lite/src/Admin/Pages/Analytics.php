<?php

namespace WPForms\Admin\Pages;

/**
 * Analytics Sub-page.
 *
 * @since 1.5.7
 */
class Analytics {

	/**
	 * Admin menu page slug.
	 *
	 * @since 1.5.7
	 *
	 * @var string
	 */
	const SLUG = 'wpforms-analytics';

	/**
	 * Configuration.
	 *
	 * @since 1.5.7
	 *
	 * @var array
	 */
	private $config = [
		'lite_plugin'         => 'google-analytics-for-wordpress/googleanalytics.php',
		'lite_wporg_url'      => 'https://wordpress.org/plugins/google-analytics-for-wordpress/',
		'lite_download_url'   => 'https://downloads.wordpress.org/plugin/google-analytics-for-wordpress.zip',
		'pro_plugin'          => 'google-analytics-premium/googleanalytics-premium.php',
		'forms_addon'         => 'monsterinsights-forms/monsterinsights-forms.php',
		'mi_forms_addon_page' => 'https://www.monsterinsights.com/addon/forms/?utm_source=wpformsplugin&utm_medium=link&utm_campaign=analytics-page',
		'mi_onboarding'       => 'admin.php?page=monsterinsights-onboarding',
		'mi_addons'           => 'admin.php?page=monsterinsights_settings#/addons',
		'mi_forms'            => 'admin.php?page=monsterinsights_reports#/forms',
	];

	/**
	 * Runtime data used for generating page HTML.
	 *
	 * @since 1.5.7
	 *
	 * @var array
	 */
	private $output_data = [];

	/**
	 * Constructor.
	 *
	 * @since 1.5.7
	 */
	public function __construct() {

		if ( ! \wpforms_current_user_can() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.5.7
	 */
	public function hooks() {

		if ( wp_doing_ajax() ) {
			add_action( 'wp_ajax_wpforms_analytics_page_check_plugin_status', [ $this, 'ajax_check_plugin_status' ] );
		}

		// Check what page we are on.
		$page = isset( $_GET['page'] ) ? \sanitize_key( \wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.CSRF.NonceVerification

		// Only load if we are actually on the Analytics page.
		if ( self::SLUG !== $page ) {
			return;
		}

		add_action( 'admin_init', [ $this, 'redirect_to_mi_forms' ] );
		add_filter( 'wpforms_admin_header', '__return_false' );
		add_action( 'wpforms_admin_page', [ $this, 'output' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );

		// Hook for addons.
		do_action( 'wpforms_admin_pages_analytics_hooks' );
	}

	/**
	 * Enqueue JS and CSS files.
	 *
	 * @since 1.5.7
	 */
	public function enqueue_assets() {

		$min = \wpforms_get_min_suffix();

		// Lity.
		wp_enqueue_style(
			'wpforms-lity',
			WPFORMS_PLUGIN_URL . 'assets/lib/lity/lity.min.css',
			null,
			'3.0.0'
		);

		wp_enqueue_script(
			'wpforms-lity',
			WPFORMS_PLUGIN_URL . 'assets/lib/lity/lity.min.js',
			[ 'jquery' ],
			'3.0.0',
			true
		);

		wp_enqueue_script(
			'wpforms-admin-page-analytics',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/pages/mi-analytics{$min}.js",
			[ 'jquery' ],
			WPFORMS_VERSION,
			true
		);

		\wp_localize_script(
			'wpforms-admin-page-analytics',
			'wpforms_pluginlanding',
			$this->get_js_strings()
		);
	}

	/**
	 * JS Strings.
	 *
	 * @since 1.5.7
	 *
	 * @return array Array of strings.
	 */
	protected function get_js_strings() {

		$error_could_not_install = sprintf(
			wp_kses( /* translators: %s - Lite plugin download URL. */
				__( 'Could not install the plugin automatically. Please <a href="%s">download</a> it and install it manually.', 'wpforms-lite' ),
				[
					'a' => [
						'href' => true,
					],
				]
			),
			esc_url( $this->config['lite_download_url'] )
		);

		$error_could_not_activate = sprintf(
			wp_kses( /* translators: %s - Lite plugin download URL. */
				__( 'Could not activate the plugin. Please activate it on the <a href="%s">Plugins page</a>.', 'wpforms-lite' ),
				[
					'a' => [
						'href' => true,
					],
				]
			),
			esc_url( admin_url( 'plugins.php' ) )
		);

		return [
			'installing'               => esc_html__( 'Installing...', 'wpforms-lite' ),
			'activating'               => esc_html__( 'Activating...', 'wpforms-lite' ),
			'activated'                => esc_html__( 'MonsterInsights Installed & Activated', 'wpforms-lite' ),
			'install_now'              => esc_html__( 'Install Now', 'wpforms-lite' ),
			'activate_now'             => esc_html__( 'Activate Now', 'wpforms-lite' ),
			'download_now'             => esc_html__( 'Download Now', 'wpforms-lite' ),
			'plugins_page'             => esc_html__( 'Go to Plugins page', 'wpforms-lite' ),
			'error_could_not_install'  => $error_could_not_install,
			'error_could_not_activate' => $error_could_not_activate,
			'mi_manual_install_url'    => $this->config['lite_download_url'],
			'mi_manual_activate_url'   => admin_url( 'plugins.php' ),
		];
	}

	/**
	 * Generate and output page HTML.
	 *
	 * @since 1.5.7
	 */
	public function output() {

		echo '<div id="wpforms-admin-analytics" class="wrap wpforms-admin-wrap wpforms-admin-plugin-landing">';

		$this->output_section_heading();
		$this->output_section_screenshot();
		$this->output_section_step_install();
		$this->output_section_step_setup();
		$this->output_section_step_addon();

		echo '</div>';
	}

	/**
	 * Generate and output heading section HTML.
	 *
	 * @since 1.5.7
	 */
	public function output_section_heading() {

		// Heading section.
		printf(
			'<section class="top">
				<img class="img-top" src="%1$s" srcset="%2$s 2x" alt="%3$s"/>
				<h1>%4$s</h1>
				<p>%5$s</p>
			</section>',
			esc_url( WPFORMS_PLUGIN_URL . 'assets/images/analytics/wpforms-monsterinsights.png' ),
			esc_url( WPFORMS_PLUGIN_URL . 'assets/images/analytics/wpforms-monsterinsights@2x.png' ),
			esc_attr__( 'WPForms ♥ MonsterInsights', 'wpforms-lite' ),
			esc_html__( 'The Best Google Analytics Plugin for WordPress', 'wpforms-lite' ),
			esc_html__( 'MonsterInsights connects WPForms to Google Analytics, providing a powerful integration with their Forms addon. MonsterInsights is a sister company of WPForms.', 'wpforms-lite' )
		);
	}

	/**
	 * Generate and output heading section HTML.
	 *
	 * @since 1.5.7
	 */
	protected function output_section_screenshot() {

		// Screenshot section.
		printf(
			'<section class="screenshot">
				<div class="cont">
					<img src="%1$s" alt="%2$s"/>
					<a href="%3$s" class="hover" data-lity></a>
				</div>
				<ul>
					<li>%4$s</li>
					<li>%5$s</li>
					<li>%6$s</li>
					<li>%7$s</li>
				</ul>			
			</section>',
			esc_url( WPFORMS_PLUGIN_URL . 'assets/images/analytics/screenshot-tnail.jpg' ),
			esc_attr__( 'Analytics screenshot', 'wpforms-lite' ),
			esc_url( WPFORMS_PLUGIN_URL . 'assets/images/analytics/screenshot-full.jpg' ),
			esc_html__( 'Track form impressions and conversions.', 'wpforms-lite' ),
			esc_html__( 'View form conversion rates from WordPress.', 'wpforms-lite' ),
			esc_html__( 'Complete UTM tracking with form entries.', 'wpforms-lite' ),
			esc_html__( 'Automatic integration with WPForms.', 'wpforms-lite' )
		);
	}

	/**
	 * Generate and output step 'Install' section HTML.
	 *
	 * @since 1.5.7
	 */
	protected function output_section_step_install() {

		$step = $this->get_data_step_install();

		if ( empty( $step ) ) {
			return;
		}

		$button_format       = '<button class="button %3$s" data-plugin="%1$s" data-action="%4$s">%2$s</button>';
		$button_allowed_html = [
			'button' => [
				'class'       => true,
				'data-plugin' => true,
				'data-action' => true,
			],
		];

		if (
			! $this->output_data['plugin_installed'] &&
			! $this->output_data['pro_plugin_installed'] &&
			! wpforms_can_install( 'plugin' )
		) {
			$button_format       = '<a class="link" href="%1$s" target="_blank" rel="nofollow noopener">%2$s <span aria-hidden="true" class="dashicons dashicons-external"></span></a>';
			$button_allowed_html = [
				'a'    => [
					'class'  => true,
					'href'   => true,
					'target' => true,
					'rel'    => true,
				],
				'span' => [
					'class'       => true,
					'aria-hidden' => true,
				],
			];
		}

		$button = sprintf( $button_format, esc_attr( $step['plugin'] ), esc_html( $step['button_text'] ), esc_attr( $step['button_class'] ), esc_attr( $step['button_action'] ) );

		printf(
			'<section class="step step-install">
				<aside class="num">
					<img src="%1$s" alt="%2$s" />
					<i class="loader hidden"></i>
				</aside>
				<div>
					<h2>%3$s</h2>
					<p>%4$s</p>
					%5$s
				</div>
			</section>',
			esc_url( WPFORMS_PLUGIN_URL . 'assets/images/' . $step['icon'] ),
			esc_attr__( 'Step 1', 'wpforms-lite' ),
			esc_html( $step['heading'] ),
			esc_html( $step['description'] ),
			wp_kses( $button, $button_allowed_html )
		);
	}

	/**
	 * Generate and output step 'Setup' section HTML.
	 *
	 * @since 1.5.7
	 */
	protected function output_section_step_setup() {

		$step = $this->get_data_step_setup();

		if ( empty( $step ) ) {
			return;
		}

		printf(
			'<section class="step step-setup %1$s">
				<aside class="num">
					<img src="%2$s" alt="%3$s" />
					<i class="loader hidden"></i>
				</aside>
				<div>
					<h2>%4$s</h2>
					<p>%5$s</p>
					<button class="button %6$s" data-url="%7$s">%8$s</button>
				</div>		
			</section>',
			esc_attr( $step['section_class'] ),
			esc_url( WPFORMS_PLUGIN_URL . 'assets/images/' . $step['icon'] ),
			esc_attr__( 'Step 2', 'wpforms-lite' ),
			esc_html__( 'Setup MonsterInsights', 'wpforms-lite' ),
			esc_html__( 'MonsterInsights has an intuitive setup wizard to guide you through the setup process.', 'wpforms-lite' ),
			esc_attr( $step['button_class'] ),
			esc_url( admin_url( $this->config['mi_onboarding'] ) ),
			esc_html( $step['button_text'] )
		);
	}

	/**
	 * Generate and output step 'Addon' section HTML.
	 *
	 * @since 1.5.7
	 */
	protected function output_section_step_addon() {

		$step = $this->get_data_step_addon();

		if ( empty( $step ) ) {
			return;
		}

		printf(
			'<section class="step step-addon %1$s">
				<aside class="num">
					<img src="%2$s" alt="%3$s" />
					<i class="loader hidden"></i>
				</aside>
				<div>
					<h2>%4$s</h2>
					<p>%5$s</p>
					<button class="button %6$s" data-url="%7$s">%8$s</button>
				</div>		
			</section>',
			esc_attr( $step['section_class'] ),
			esc_url( WPFORMS_PLUGIN_URL . 'assets/images/step-3.svg' ),
			esc_attr__( 'Step 3', 'wpforms-lite' ),
			esc_html__( 'Get Form Conversion Tracking', 'wpforms-lite' ),
			esc_html__( 'With the MonsterInsights Form addon you can easily track your form views, entries, conversion rates, and more.', 'wpforms-lite' ),
			esc_attr( $step['button_class'] ),
			esc_url( $step['button_url'] ),
			esc_html( $step['button_text'] )
		);
	}

	/**
	 * Step 'Install' data.
	 *
	 * @since 1.5.7
	 *
	 * @return array Step data.
	 */
	protected function get_data_step_install() {

		$step                = [];
		$step['heading']     = esc_html__( 'Install & Activate MonsterInsights', 'wpforms-lite' );
		$step['description'] = esc_html__( 'Track form impressions and conversions.', 'wpforms-lite' );

		$this->output_data['all_plugins']          = get_plugins();
		$this->output_data['plugin_installed']     = array_key_exists( $this->config['lite_plugin'], $this->output_data['all_plugins'] );
		$this->output_data['plugin_activated']     = false;
		$this->output_data['pro_plugin_installed'] = array_key_exists( $this->config['pro_plugin'], $this->output_data['all_plugins'] );
		$this->output_data['pro_plugin_activated'] = false;

		if ( ! $this->output_data['plugin_installed'] && ! $this->output_data['pro_plugin_installed'] ) {
			$step['icon']          = 'step-1.svg';
			$step['button_text']   = esc_html__( 'Install MonsterInsights', 'wpforms-lite' );
			$step['button_class']  = 'button-primary';
			$step['button_action'] = 'install';
			$step['plugin']        = $this->config['lite_download_url'];

			if ( ! wpforms_can_install( 'plugin' ) ) {
				$step['heading']     = esc_html__( 'MonsterInsights', 'wpforms-lite' );
				$step['description'] = '';
				$step['button_text'] = esc_html__( 'MonsterInsights on WordPress.org', 'wpforms-lite' );
				$step['plugin']      = $this->config['lite_wporg_url'];
			}
		} else {
			$this->output_data['plugin_activated'] = is_plugin_active( $this->config['lite_plugin'] ) || is_plugin_active( $this->config['pro_plugin'] );
			$step['icon']                          = $this->output_data['plugin_activated'] ? 'step-complete.svg' : 'step-1.svg';
			$step['button_text']                   = $this->output_data['plugin_activated'] ? esc_html__( 'MonsterInsights Installed & Activated', 'wpforms-lite' ) : esc_html__( 'Activate MonsterInsights', 'wpforms-lite' );
			$step['button_class']                  = $this->output_data['plugin_activated'] ? 'grey disabled' : 'button-primary';
			$step['button_action']                 = $this->output_data['plugin_activated'] ? '' : 'activate';
			$step['plugin']                        = $this->output_data['pro_plugin_installed'] ? $this->config['pro_plugin'] : $this->config['lite_plugin'];
		}

		return $step;
	}

	/**
	 * Step 'Setup' data.
	 *
	 * @since 1.5.7
	 *
	 * @return array Step data.
	 */
	protected function get_data_step_setup() {

		$step = [];

		$this->output_data['plugin_setup'] = false;
		if ( $this->output_data['plugin_activated'] ) {
			$this->output_data['plugin_setup'] = '' !== (string) \monsterinsights_get_ua();
		}

		$step['icon']          = 'step-2.svg';
		$step['section_class'] = $this->output_data['plugin_activated'] ? '' : 'grey';
		$step['button_text']   = esc_html__( 'Run Setup Wizard', 'wpforms-lite' );
		$step['button_class']  = 'grey disabled';

		if ( $this->output_data['plugin_setup'] ) {
			$step['icon']          = 'step-complete.svg';
			$step['section_class'] = '';
			$step['button_text']   = esc_html__( 'Setup Complete', 'wpforms-lite' );
		} else {
			$step['button_class'] = $this->output_data['plugin_activated'] ? 'button-primary' : 'grey disabled';
		}

		return $step;
	}

	/**
	 * Step 'Addon' data.
	 *
	 * @since 1.5.7
	 *
	 * @return array Step data.
	 */
	protected function get_data_step_addon() {

		$step = [];

		$step['icon']          = 'step-3.svg';
		$step['section_class'] = $this->output_data['plugin_setup'] ? '' : 'grey';
		$step['button_text']   = esc_html__( 'Learn More', 'wpforms-lite' );
		$step['button_class']  = 'grey disabled';
		$step['button_url']    = '';

		$plugin_license_level = false;
		if ( $this->output_data['plugin_activated'] ) {
			$mi = \MonsterInsights();

			$plugin_license_level = 'lite';
			if ( is_object( $mi->license ) && method_exists( $mi->license, 'license_can' ) ) {
				$plugin_license_level = $mi->license->license_can( 'plus' ) ? 'lite' : $plugin_license_level;
				$plugin_license_level = $mi->license->license_can( 'pro' ) || $mi->license->license_can( 'agency' ) ? 'pro' : $plugin_license_level;
			}
		}

		switch ( $plugin_license_level ) {
			case 'lite':
				$step['button_url']   = $this->config['mi_forms_addon_page'];
				$step['button_class'] = $this->output_data['plugin_setup'] ? 'button-primary' : 'grey';
				break;

			case 'pro':
				$addon_installed      = array_key_exists( $this->config['forms_addon'], $this->output_data['all_plugins'] );
				$step['button_text']  = $addon_installed ? esc_html__( 'Activate Now', 'wpforms-lite' ) : esc_html__( 'Install Now', 'wpforms-lite' );
				$step['button_url']   = admin_url( $this->config['mi_addons'] );
				$step['button_class'] = $this->output_data['plugin_setup'] ? 'button-primary' : 'grey';
				break;
		}

		return $step;
	}

	/**
	 * Ajax endpoint. Check plugin setup status.
	 * Used to properly init step 2 section after completing step 1.
	 *
	 * @since 1.5.7
	 */
	public function ajax_check_plugin_status() {

		// Security checks.
		if (
			! check_ajax_referer( 'wpforms-admin', 'nonce', false ) ||
			! wpforms_current_user_can()
		) {
			wp_send_json_error(
				[
					'error' => esc_html__( 'You do not have permission.', 'wpforms-lite' ),
				]
			);
		}

		$result = [];

		if ( ! function_exists( 'MonsterInsights' ) || ! function_exists( 'monsterinsights_get_ua' ) ) {
			wp_send_json_error(
				[
					'error' => esc_html__( 'Plugin unavailable.', 'wpforms-lite' ),
				]
			);
		}

		$result['setup_status'] = (int) ( '' !== (string) \monsterinsights_get_ua() );

		$mi = \MonsterInsights();

		$result['license_level']    = 'lite';
		$result['step3_button_url'] = $this->config['mi_forms_addon_page'];
		if ( is_object( $mi->license ) && method_exists( $mi->license, 'license_can' ) ) {
			$result['license_level']    = $mi->license->license_can( 'pro' ) || $mi->license->license_can( 'agency' ) ? 'pro' : $result['license_level'];
			$result['step3_button_url'] = admin_url( $this->config['mi_addons'] );
		}

		$result['addon_installed'] = (int) array_key_exists( $this->config['forms_addon'], get_plugins() );

		wp_send_json_success( $result );
	}

	/**
	 * Redirect to MI forms reporting page.
	 * We need this function because `is_plugin_active()` available only after `admin_init` action.
	 *
	 * @since 1.5.7
	 */
	public function redirect_to_mi_forms() {

		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		// Redirect to MI Forms addon if it is activated.
		if ( is_plugin_active( $this->config['forms_addon'] ) ) {
			wp_safe_redirect( admin_url( $this->config['mi_forms'] ) );
			exit;
		}
	}
}
