<?php

namespace WPForms\Lite\Admin\Pages;

/**
 * Addons page for Lite.
 *
 * @since 1.6.7
 */
class Addons {

	/**
	 * Page slug.
	 *
	 * @since 1.6.7
	 *
	 * @type string
	 */
	const SLUG = 'addons';

	/**
	 * Determine if current class is allowed to load.
	 *
	 * @since 1.6.7
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page( self::SLUG );
	}

	/**
	 * Init.
	 *
	 * @since 1.6.7
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
	 * @since 1.6.7
	 */
	public function hooks() {

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
		add_action( 'admin_notices', [ $this, 'notices' ] );
		add_action( 'wpforms_admin_page', [ $this, 'output' ] );
	}

	/**
	 * Add appropriate scripts to the Addons page.
	 *
	 * @since 1.6.7
	 */
	public function enqueues() {

		// JavaScript.
		wp_enqueue_script(
			'listjs',
			WPFORMS_PLUGIN_URL . 'assets/lib/list.min.js',
			[ 'jquery' ],
			'1.5.0'
		);
	}

	/**
	 * Notices.
	 *
	 * @since 1.6.7.1
	 */
	public function notices() {

		$notice = sprintf(
			'<p><strong>%1$s</strong></p>
             <p>%2$s</p>
             <p>
                 <a href="%3$s" class="wpforms-btn wpforms-btn-orange wpforms-btn-md" target="_blank" rel="noopener noreferrer">
                     %4$s
                 </a>
             </p>',
			esc_html__( 'WPForms Addons are a PRO feature', 'wpforms-lite' ),
			esc_html__( 'Please upgrade to PRO to unlock our addons, advanced form fields, and more!', 'wpforms-lite' ),
			esc_url( wpforms_admin_upgrade_link( 'addons', 'All Addons' ) ),
			esc_html__( 'Upgrade Now', 'wpforms-lite' )
		);

		\WPForms\Admin\Notice::info(
			$notice,
			[ 'autop' => false ]
		);
	}

	/**
	 * Render the Addons page.
	 *
	 * @since 1.6.7
	 */
	public function output() {

		$addons = wpforms()->get( 'addons' )->get_all();

		if ( empty( $addons ) ) {
			return;
		}

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'admin/addons',
			[
				'upgrade_link_base' => wpforms_admin_upgrade_link( 'addons' ),
				'addons'            => $addons,
			],
			true
		);
	}
}
