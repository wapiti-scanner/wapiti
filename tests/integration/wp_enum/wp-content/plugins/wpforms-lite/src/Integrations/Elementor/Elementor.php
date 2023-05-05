<?php

namespace WPForms\Integrations\Elementor;

use Elementor\Plugin as ElementorPlugin;
use WPForms\Integrations\IntegrationInterface;

/**
 * Improve Elementor Compatibility.
 *
 * @since 1.6.0
 */
class Elementor implements IntegrationInterface {

	/**
	 * Indicates if current integration is allowed to load.
	 *
	 * @since 1.6.0
	 *
	 * @return bool
	 */
	public function allow_load() {

		return (bool) did_action( 'elementor/loaded' );
	}

	/**
	 * Load an integration.
	 *
	 * @since 1.6.0
	 */
	public function load() {

		$this->hooks();
	}

	/**
	 * Integration hooks.
	 *
	 * @since 1.6.0
	 */
	protected function hooks() {

		// Skip if Elementor is not available.
		if ( ! class_exists( '\Elementor\Plugin' ) ) {
			return;
		}

		add_action( 'elementor/preview/init', [ $this, 'init' ] );
		add_action( 'elementor/frontend/after_enqueue_scripts', [ $this, 'preview_assets' ] );
		add_action( 'elementor/frontend/after_enqueue_scripts', [ $this, 'frontend_assets' ] );
		add_action( 'elementor/editor/after_enqueue_styles', [ $this, 'editor_assets' ] );

		version_compare( ELEMENTOR_VERSION, '3.5.0', '>=' ) ?
			add_action( 'elementor/widgets/register', [ $this, 'register_widget' ] ) :
			add_action( 'elementor/widgets/widgets_registered', [ $this, 'register_widget' ] );

		add_action( 'wp_ajax_wpforms_admin_get_form_selector_options', [ $this, 'ajax_get_form_selector_options' ] );
	}

	/**
	 * Init the main logic.
	 *
	 * @since 1.6.0
	 */
	public function init() {

		/**
		 * Allow developers to determine whether the compatibility layer should be applied.
		 * We do this check here because we want this filter to be available for theme developers too.
		 *
		 * @since 1.6.0
		 *
		 * @param bool $use_compat Use compatibility.
		 */
		$use_compat = (bool) apply_filters( 'wpforms_apply_elementor_preview_compat', true );

		if ( $use_compat !== true ) {
			return;
		}

		// Load WPForms assets globally on Elementor Preview panel only.
		add_filter( 'wpforms_global_assets', '__return_true' );

		// Hide CAPTCHA badge on Elementor Preview panel.
		add_filter( 'wpforms_frontend_recaptcha_disable', '__return_true' );
	}

	/**
	 * Load assets in the preview panel.
	 *
	 * @since 1.6.2
	 */
	public function preview_assets() {

		if ( ! ElementorPlugin::$instance->preview->is_preview_mode() ) {
			return;
		}

		$min = wpforms_get_min_suffix();

		wp_enqueue_style(
			'wpforms-integrations',
			WPFORMS_PLUGIN_URL . "assets/css/admin-integrations{$min}.css",
			null,
			WPFORMS_VERSION
		);

		wp_enqueue_script(
			'wpforms-elementor',
			WPFORMS_PLUGIN_URL . "assets/js/integrations/elementor/editor{$min}.js",
			[ 'elementor-frontend', 'jquery', 'wp-util' ],
			WPFORMS_VERSION,
			true
		);

		wp_localize_script(
			'wpforms-elementor',
			'wpformsElementorVars',
			[
				'ajax_url'      => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'wpforms-elementor-integration' ),
				'edit_form_url' => admin_url( 'admin.php?page=wpforms-builder&view=fields&form_id=' ),
				'add_form_url'  => admin_url( 'admin.php?page=wpforms-builder&view=setup' ),
				'css_url'       => WPFORMS_PLUGIN_URL . "assets/css/admin-integrations{$min}.css",
				'debug'         => wpforms_debug(),
			]
		);
	}

	/**
	 * Load an integration assets on the frontend.
	 *
	 * @since 1.6.2
	 */
	public function frontend_assets() {

		if ( ElementorPlugin::$instance->preview->is_preview_mode() ) {
			return;
		}

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-elementor',
			WPFORMS_PLUGIN_URL . "assets/js/integrations/elementor/frontend{$min}.js",
			[ 'elementor-frontend', 'jquery', 'wp-util' ],
			WPFORMS_VERSION,
			true
		);

		wp_localize_script(
			'wpforms-elementor',
			'wpformsElementorVars',
			[
				'captcha_provider' => wpforms_setting( 'captcha-provider', 'recaptcha' ),
				'recaptcha_type'   => wpforms_setting( 'recaptcha-type', 'v2' ),
			]
		);
	}

	/**
	 * Load assets in the elementor document.
	 *
	 * @since 1.6.2
	 */
	public function editor_assets() {

		if ( empty( $_GET['action'] ) || $_GET['action'] !== 'elementor' ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$min = wpforms_get_min_suffix();

		wp_enqueue_style(
			'wpforms-integrations',
			WPFORMS_PLUGIN_URL . "assets/css/admin-integrations{$min}.css",
			null,
			WPFORMS_VERSION
		);
	}

	/**
	 * Register WPForms Widget.
	 *
	 * @since 1.6.2
	 * @since 1.7.6 Added support for new registration method since 3.5.0.
	 */
	public function register_widget() {

		version_compare( ELEMENTOR_VERSION, '3.5.0', '>=' ) ?
			ElementorPlugin::instance()->widgets_manager->register( new Widget() ) :
			ElementorPlugin::instance()->widgets_manager->register_widget_type( new Widget() );
	}

	/**
	 * Get form selector options.
	 *
	 * @since 1.6.2
	 */
	public function ajax_get_form_selector_options() {

		check_ajax_referer( 'wpforms-elementor-integration', 'nonce' );

		wp_send_json_success( ( new Widget() )->get_form_selector_options() );
	}
}
