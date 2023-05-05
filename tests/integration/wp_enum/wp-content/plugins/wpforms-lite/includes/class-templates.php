<?php

/**
 * Pre-configured packaged templates.
 *
 * @since 1.0.0
 */
class WPForms_Templates {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		$this->init();
	}

	/**
	 * Load and init the base form template class.
	 *
	 * @since 1.2.8
	 */
	public function init() {

		// Parent class template.
		require_once WPFORMS_PLUGIN_DIR . 'includes/templates/class-base.php';

		// Load default templates on WP init.
		add_action( 'init', [ $this, 'load' ] );
	}

	/**
	 * Load default form templates.
	 *
	 * @since 1.0.0
	 */
	public function load() {

		$templates = apply_filters(
			'wpforms_load_templates',
			[
				'blank',
				'simple-contact-form',
			]
		);

		foreach ( $templates as $template ) {

			$template = sanitize_file_name( $template );

			if ( file_exists( WPFORMS_PLUGIN_DIR . 'includes/templates/class-' . $template . '.php' ) ) {
				require_once WPFORMS_PLUGIN_DIR . 'includes/templates/class-' . $template . '.php';
			} elseif ( file_exists( WPFORMS_PLUGIN_DIR . 'pro/includes/templates/class-' . $template . '.php' ) && wpforms()->is_pro() ) {
				require_once WPFORMS_PLUGIN_DIR . 'pro/includes/templates/class-' . $template . '.php';
			}
		}
	}
}

new WPForms_Templates;
