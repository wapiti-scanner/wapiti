<?php

namespace WPForms\Integrations\Divi;

use WPForms_Field_Select;
use WPForms\Integrations\IntegrationInterface;

/**
 * Class Divi.
 *
 * @since 1.6.3
 */
class Divi implements IntegrationInterface {

	/**
	 * Indicate if current integration is allowed to load.
	 *
	 * @since 1.6.3
	 *
	 * @return bool
	 */
	public function allow_load() {

		if ( function_exists( 'et_divi_builder_init_plugin' ) ) {
			return true;
		}

		$allow_themes = [ 'Divi', 'Extra' ];
		$theme        = wp_get_theme();
		$theme_name   = $theme->get_template();
		$theme_parent = $theme->parent();

		return (bool) array_intersect( [ $theme_name, $theme_parent ], $allow_themes );
	}

	/**
	 * Load an integration.
	 *
	 * @since 1.6.3
	 */
	public function load() {

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.3
	 */
	public function hooks() {

		add_action( 'et_builder_ready', [ $this, 'register_module' ] );
		add_action( 'wp_enqueue_scripts', [ $this, 'frontend_styles' ], 12 );

		if ( wp_doing_ajax() ) {
			add_action( 'wp_ajax_wpforms_divi_preview', [ $this, 'preview' ] );
		}

		if ( $this->is_divi_builder() ) {
			add_action( 'wp_enqueue_scripts', [ $this, 'builder_styles' ], 12 );
			add_action( 'wp_enqueue_scripts', [ $this, 'builder_scripts' ] );

			add_filter( 'wpforms_global_assets', '__return_true' );
			add_filter( 'wpforms_frontend_missing_assets_error_js_disable', '__return_true', PHP_INT_MAX );
		}
	}

	/**
	 * Determine if a current page is opened in the Divi Builder.
	 *
	 * @since 1.6.3
	 *
	 * @return bool
	 */
	private function is_divi_builder() {

		return ! empty( $_GET['et_fb'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}


	/**
	 * Get current style name.
	 *
	 * Overwrite styles for the Divi Builder.
	 *
	 * @since 1.6.3
	 *
	 * @return string
	 */
	public function get_current_styles_name() {

		$disable_css = absint( wpforms_setting( 'disable-css', 1 ) );

		if ( $disable_css === 3 ) {
			return '';
		}

		$styles_name  = wpforms_get_render_engine() . '-';
		$styles_name .= $disable_css === 1 ? 'full' : 'base';

		return $styles_name;
	}

	/**
	 * Determine if the Divi Builder plugin is loaded.
	 *
	 * @since 1.6.3
	 *
	 * @return bool
	 */
	protected function is_divi_plugin_loaded() {

		if ( ! is_singular() ) {
			return false;
		}

		return function_exists( 'et_is_builder_plugin_active' ) && et_is_builder_plugin_active();
	}

	/**
	 * WPForms frontend styles special for Divi.
	 *
	 * @since 1.8.1
	 */
	protected function divi_frontend_styles() {

		$min = wpforms_get_min_suffix();

		$styles_name = $this->get_current_styles_name();

		wp_enqueue_style(
			'wpforms-choicesjs',
			WPFORMS_PLUGIN_URL . "assets/css/integrations/divi/choices{$min}.css",
			[],
			WPForms_Field_Select::CHOICES_VERSION
		);

		if ( empty( $styles_name ) ) {
			return;
		}

		// Load CSS per global setting.
		wp_register_style(
			"wpforms-{$styles_name}",
			WPFORMS_PLUGIN_URL . "assets/css/integrations/divi/wpforms-{$styles_name}{$min}.css",
			[],
			WPFORMS_VERSION
		);
	}

	/**
	 * Register frontend styles.
	 * Required for the plugin version of builder only.
	 *
	 * @since 1.6.3
	 */
	public function frontend_styles() {

		if ( ! $this->is_divi_plugin_loaded() ) {
			return;
		}

		$this->divi_frontend_styles();
	}

	/**
	 * Load styles.
	 *
	 * @since 1.6.3
	 */
	public function builder_styles() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_style(
			'wpforms-integrations',
			WPFORMS_PLUGIN_URL . "assets/css/admin-integrations{$min}.css",
			null,
			WPFORMS_VERSION
		);

		$this->divi_frontend_styles();
	}

	/**
	 * Load scripts.
	 *
	 * @since 1.6.3
	 */
	public function builder_scripts() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-divi',
			WPFORMS_PLUGIN_URL . "assets/js/integrations/divi/formselector.es5{$min}.js",
			[ 'react', 'react-dom' ],
			WPFORMS_VERSION,
			true
		);

		wp_localize_script(
			'wpforms-divi',
			'wpforms_divi_builder',
			[
				'ajax_url'          => admin_url( 'admin-ajax.php' ),
				'nonce'             => wp_create_nonce( 'wpforms_divi_builder' ),
				'placeholder'       => WPFORMS_PLUGIN_URL . 'assets/images/sullie-alt.png',
				'placeholder_title' => esc_html__( 'WPForms', 'wpforms-lite' ),
			]
		);
	}

	/**
	 * Register module.
	 *
	 * @since 1.6.3
	 */
	public function register_module() {

		if ( ! class_exists( 'ET_Builder_Module' ) ) {
			return;
		}

		new WPFormsSelector();
	}

	/**
	 * Ajax handler for the form preview.
	 *
	 * @since 1.6.3
	 */
	public function preview() {

		check_ajax_referer( 'wpforms_divi_builder', 'nonce' );

		$form_id    = absint( filter_input( INPUT_POST, 'form_id', FILTER_SANITIZE_NUMBER_INT ) );
		$show_title = 'on' === filter_input( INPUT_POST, 'show_title', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
		$show_desc  = 'on' === filter_input( INPUT_POST, 'show_desc', FILTER_SANITIZE_FULL_SPECIAL_CHARS );

		add_filter(
			'wpforms_frontend_container_class',
			function( $classes ) {

				$classes[] = 'wpforms-gutenberg-form-selector';
				$classes[] = 'wpforms-container-full';

				return $classes;
			}
		);

		add_action(
			'wpforms_frontend_output',
			function() {

				echo '<fieldset disabled>';
			},
			3
		);

		add_action(
			'wpforms_frontend_output',
			function() {

				echo '</fieldset>';

				// This empty image is needed to execute JS code that triggers the custom event.
				// Unfortunately, <script> tag doesn't work in the Divi Builder.
				echo "<img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
					height='0'
					width='0'
					onLoad=\"jQuery( document ).trigger( 'wpformsDiviModuleDisplay' );\"
				/>";
			},
			30
		);

		wp_send_json_success(
			do_shortcode(
				sprintf(
					'[wpforms id="%1$s" title="%2$s" description="%3$s"]',
					absint( $form_id ),
					(bool) apply_filters( 'wpforms_divi_builder_form_title', $show_title, $form_id ),
					(bool) apply_filters( 'wpforms_divi_builder_form_desc', $show_desc, $form_id )
				)
			)
		);
	}
}
