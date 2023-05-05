<?php

namespace WPForms\Admin\Pages;

/**
 * Constant Contact Sub-page.
 *
 * @since 1.7.3
 */
class ConstantContact {

	/**
	 * Determine if the class is allowed to be loaded.
	 *
	 * @since 1.7.3
	 */
	private function allow_load() {

		return wpforms_is_admin_page( 'page', 'constant-contact' );
	}

	/**
	 * Initialize class.
	 *
	 * @since 1.7.3
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.3
	 */
	private function hooks() {

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
		add_action( 'wpforms_admin_page', [ $this, 'view' ] );
	}

	/**
	 * Enqueue JS and CSS files.
	 *
	 * @since 1.7.3
	 */
	public function enqueue_assets() {

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
	}

	/**
	 * Page view.
	 *
	 * @since 1.7.3
	 */
	public function view() {

		$sign_up_link = get_option( 'wpforms_constant_contact_signup', 'https://constant-contact.evyy.net/c/11535/341874/3411?sharedid=wpforms' );

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render(
			'admin/pages/constant-contact',
			[
				'sign_up_link'           => is_string( $sign_up_link ) ? $sign_up_link : '',
				'wpbeginners_guide_link' => 'https://www.wpbeginner.com/beginners-guide/why-you-should-start-building-your-email-list-right-away',
			],
			true
		);
	}
}
