<?php

namespace WPForms\Admin\Education;

/**
 * Education core.
 *
 * @since 1.6.6
 */
class Core {

	/**
	 * Indicate if Education core is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wp_doing_ajax() || wpforms_is_admin_page() || wpforms_is_admin_page( 'builder' );
	}

	/**
	 * Init.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		// Only proceed if allowed.
		if ( ! $this->allow_load() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	protected function hooks() {

		if ( wp_doing_ajax() ) {
			add_action( 'wp_ajax_wpforms_education_dismiss', [ $this, 'ajax_dismiss' ] );

			return;
		}

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
	}

	/**
	 * Load enqueues.
	 *
	 * @since 1.6.6
	 */
	public function enqueues() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-admin-education-core',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/education/core{$min}.js",
			[ 'jquery', 'jquery-confirm' ],
			WPFORMS_VERSION,
			true
		);

		wp_localize_script(
			'wpforms-admin-education-core',
			'wpforms_education',
			(array) apply_filters( 'wpforms_admin_education_strings', $this->get_js_strings() )
		);
	}

	/**
	 * Localize common strings.
	 *
	 * @since 1.6.6
	 *
	 * @return array
	 */
	protected function get_js_strings() {

		$strings = [];

		$strings['ok']                 = esc_html__( 'Ok', 'wpforms-lite' );
		$strings['cancel']             = esc_html__( 'Cancel', 'wpforms-lite' );
		$strings['close']              = esc_html__( 'Close', 'wpforms-lite' );
		$strings['ajax_url']           = admin_url( 'admin-ajax.php' );
		$strings['nonce']              = wp_create_nonce( 'wpforms-education' );
		/* translators: %s - addon name. */
		$strings['activate_prompt']    = '<p>' . esc_html( sprintf( __( 'The %s is installed but not activated. Would you like to activate it?', 'wpforms-lite' ), '%name%' ) ) . '</p>';
		$strings['activate_confirm']   = esc_html__( 'Yes, activate', 'wpforms-lite' );
		$strings['addon_activated']    = esc_html__( 'Addon activated', 'wpforms-lite' );
		$strings['plugin_activated']   = esc_html__( 'Plugin activated', 'wpforms-lite' );
		$strings['activating']         = esc_html__( 'Activating', 'wpforms-lite' );
		/* translators: %s - addon name. */
		$strings['install_prompt']     = '<p>' . esc_html( sprintf( __( 'The %s is not installed. Would you like to install and activate it?', 'wpforms-lite' ), '%name%' ) ) . '</p>';
		$strings['install_confirm']    = esc_html__( 'Yes, install and activate', 'wpforms-lite' );
		$strings['installing']         = esc_html__( 'Installing', 'wpforms-lite' );
		$strings['can_install_addons'] = wpforms_can_install( 'addon' );
		$strings['save_prompt']        = esc_html__( 'Almost done! Would you like to save and refresh the form builder?', 'wpforms-lite' );
		$strings['save_confirm']       = esc_html__( 'Yes, save and refresh', 'wpforms-lite' );
		$strings['saving']             = esc_html__( 'Saving ...', 'wpforms-lite' );

		if ( ! $strings['can_install_addons'] ) {
			/* translators: %s - addon name. */
			$strings['install_prompt'] = '<p>' . esc_html( sprintf( __( 'The %s is not installed. Please install and activate it to use this feature.', 'wpforms-lite' ), '%name%' ) ) . '</p>';
		}

		$upgrade_utm_medium = wpforms_is_admin_page() ? 'Settings - Integration' : 'Builder - Settings';

		$strings['upgrade'] = [
			'pro'   => [
				'title'        => esc_html__( 'is a PRO Feature', 'wpforms-lite' ),
				/* translators: %s - addon name. */
				'message'      => '<p>' . esc_html( sprintf( __( 'We\'re sorry, the %s is not available on your plan. Please upgrade to the PRO plan to unlock all these awesome features.', 'wpforms-lite' ), '%name%' ) ) . '</p>',
				'doc'          => sprintf(
					'<a href="%1$s" target="_blank" rel="noopener noreferrer" class="already-purchased">%2$s</a>',
					esc_url( wpforms_utm_link( 'https://wpforms.com/docs/upgrade-wpforms-lite-paid-license/#installing-wpforms', $upgrade_utm_medium, 'AP - %name%' ) ),
					esc_html__( 'Already purchased?', 'wpforms-lite' )
				),
				'button'       => esc_html__( 'Upgrade to PRO', 'wpforms-lite' ),
				'url'          => wpforms_admin_upgrade_link( $upgrade_utm_medium ),
				'url_template' => wpforms_is_admin_page( 'templates' ) ? wpforms_admin_upgrade_link( 'Form Templates Subpage' ) : wpforms_admin_upgrade_link( 'builder-modal-template' ),
				'modal'        => wpforms_get_upgrade_modal_text( 'pro' ),
			],
			'elite' => [
				'title'        => esc_html__( 'is an Elite Feature', 'wpforms-lite' ),
				/* translators: %s - addon name. */
				'message'      => '<p>' . esc_html( sprintf( __( 'We\'re sorry, the %s is not available on your plan. Please upgrade to the Elite plan to unlock all these awesome features.', 'wpforms-lite' ), '%name%' ) ) . '</p>',
				'doc'          => sprintf(
					'<a href="%1$s" target="_blank" rel="noopener noreferrer" class="already-purchased">%2$s</a>',
					esc_url( wpforms_utm_link( 'https://wpforms.com/docs/upgrade-wpforms-lite-paid-license/#installing-wpforms', $upgrade_utm_medium, 'AP - %name%' ) ),
					esc_html__( 'Already purchased?', 'wpforms-lite' )
				),
				'button'       => esc_html__( 'Upgrade to Elite', 'wpforms-lite' ),
				'url'          => wpforms_admin_upgrade_link( $upgrade_utm_medium ),
				'url_template' => wpforms_is_admin_page( 'templates' ) ? wpforms_admin_upgrade_link( 'Form Templates Subpage' ) : wpforms_admin_upgrade_link( 'builder-modal-template' ),
				'modal'        => wpforms_get_upgrade_modal_text( 'elite' ),
			],
		];

		$strings['upgrade_bonus'] = wpautop(
			wp_kses(
				__( '<strong>Bonus:</strong> WPForms Lite users get <span>50% off</span> regular price, automatically applied at checkout.', 'wpforms-lite' ),
				[
					'strong' => [],
					'span'   => [],
				]
			)
		);

		$strings['thanks_for_interest'] = esc_html__( 'Thanks for your interest in WPForms Pro!', 'wpforms-lite' );

		return $strings;
	}

	/**
	 * Ajax handler for the education dismiss buttons.
	 *
	 * @since 1.6.6
	 */
	public function ajax_dismiss() {

		// Run a security check.
		check_ajax_referer( 'wpforms-education', 'nonce' );

		// Section is the identifier of the education feature.
		// For example: in Builder/DidYouKnow feature used 'builder-did-you-know-notifications' and 'builder-did-you-know-confirmations'.
		$section = ! empty( $_POST['section'] ) ? sanitize_key( $_POST['section'] ) : '';

		if ( empty( $section ) ) {
			wp_send_json_error(
				[ 'error' => esc_html__( 'Please specify a section.', 'wpforms-lite' ) ]
			);
		}

		// Check for permissions.
		if ( ! $this->current_user_can() ) {
			wp_send_json_error(
				[ 'error' => esc_html__( 'You do not have permission to perform this action.', 'wpforms-lite' ) ]
			);
		}

		$user_id   = get_current_user_id();
		$dismissed = get_user_meta( $user_id, 'wpforms_dismissed', true );

		if ( empty( $dismissed ) ) {
			$dismissed = [];
		}

		$dismissed[ 'edu-' . $section ] = time();

		update_user_meta( $user_id, 'wpforms_dismissed', $dismissed );
		wp_send_json_success();
	}

	/**
	 * Whether the current user can perform an action.
	 *
	 * @since 1.8.0
	 *
	 * @return bool
	 */
	private function current_user_can() {

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$page = ! empty( $_POST['page'] ) ? sanitize_key( $_POST['page'] ) : '';

		// key is the same as $current_screen->id and the JS global 'pagenow', value - capability name(s).
		$caps = [
			'toplevel_page_wpforms-overview' => [ 'view_forms' ],
			'wpforms_page_wpforms-builder'   => [ 'edit_forms' ],
			'wpforms_page_wpforms-entries'   => [ 'view_entries' ],
		];

		return isset( $caps[ $page ] ) ? wpforms_current_user_can( $caps[ $page ] ) : wpforms_current_user_can();
	}
}
