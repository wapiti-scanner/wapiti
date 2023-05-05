<?php

namespace WPForms\Providers;

/**
 * Class Providers gives ability to track/load all providers.
 *
 * @since 1.4.7
 * @since 1.7.3 Renamed from `Loader` to `Providers`.
 */
class Providers {

	/**
	 * Get the instance of a class and store it in itself.
	 * Later we will be able to use this class as `$providers_loader = \WPForms\Providers\Providers::get_instance();`.
	 *
	 * @since 1.4.7
	 */
	public static function get_instance() {

		static $instance;

		if ( ! $instance ) {
			$instance = new Providers();
		}

		return $instance;
	}

	/**
	 * Loader constructor.
	 *
	 * @since 1.4.7
	 */
	public function __construct() {
	}

	/**
	 * Register a provider.
	 *
	 * @since 1.4.7
	 *
	 * @param \WPForms\Providers\Provider\Core $provider The core class of a single provider.
	 */
	public function register( Provider\Core $provider ) {

		add_filter( 'wpforms_providers_available', [ $provider, 'register_provider' ] );

		// WPForms > Settings > Integrations page.
		$integration = $provider->get_page_integrations();

		if ( $integration !== null ) {
			add_action( 'wpforms_settings_providers', [ $integration, 'display' ], $provider::PRIORITY, 2 );
		}

		// Editing Single Form > Form Builder.
		$form_builder = $provider->get_form_builder();

		if ( $form_builder !== null ) {
			add_action( 'wpforms_providers_panel_sidebar', [ $form_builder, 'display_sidebar' ], $provider::PRIORITY );
			add_action( 'wpforms_providers_panel_content', [ $form_builder, 'display_content' ], $provider::PRIORITY );
		}

		// Process entry submission.
		$process = $provider->get_process();

		if ( $process !== null ) {
			add_action( 'wpforms_process_complete', [ $process, 'process' ], 5, 4 );
		}
	}

}
