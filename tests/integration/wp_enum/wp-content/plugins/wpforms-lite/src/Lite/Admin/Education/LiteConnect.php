<?php

namespace WPForms\Lite\Admin\Education;

use WPForms\Admin\Education;
use WPForms\Integrations\LiteConnect\API;
use WPForms\Lite\Integrations\LiteConnect\LiteConnect as LiteConnectClass;
use WPForms\Lite\Integrations\LiteConnect\Integration as LiteConnectIntegration;

/**
 * Admin/Settings/LiteConnect Education feature for Lite.
 *
 * @since 1.7.4
 */
class LiteConnect implements Education\EducationInterface {

	/**
	 * Indicate if Lite Connect entry backup is enabled.
	 *
	 * @since 1.7.4
	 *
	 * @var int
	 */
	private $is_enabled;

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.7.4
	 *
	 * @return bool
	 */
	public function allow_load() {

		// Do not load if Lite Connect integration is not allowed.
		if ( ! LiteConnectClass::is_allowed() ) {
			return false;
		}

		// Do not load if user doesn't have permissions to update settings.
		if ( ! wpforms_current_user_can( wpforms_get_capability_manage_options() ) ) {
			return false;
		}

		// Load only in certain cases.
		return wp_doing_ajax() ||
			wpforms_is_admin_page( 'builder' ) ||
			wpforms_is_admin_page( 'settings' ) ||
			wpforms_is_admin_page( 'overview' ) ||
			wpforms_is_admin_page( 'entries' ) ||
			$this->is_dashboard() ||
			$this->is_embed_page();
	}

	/**
	 * Init.
	 *
	 * @since 1.7.4
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->is_enabled = LiteConnectClass::is_enabled() ? 1 : 0;

		// Define hooks.
		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.4
	 */
	private function hooks() {

		add_action( 'admin_footer', [ $this, 'modal_template' ], 10, 2 );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );

		// Ajax action.
		add_action( 'wp_ajax_wpforms_update_lite_connect_enabled_setting', [ $this, 'ajax_update_lite_connect_enabled_setting' ] );

		// Content filters.
		add_filter( 'wpforms_lite_admin_dashboard_widget_content_html_chart_block_before', [ $this, 'dashboard_widget_before_content' ] );
		add_filter( 'wpforms_builder_output_before_toolbar', [ $this, 'top_bar_content' ] );
		add_filter( 'wpforms_admin_challenge_embed_template_congrats_popup_footer', [ $this, 'challenge_popup_footer_content' ] );
	}

	/**
	 * Check whether it is the Dashboard admin page.
	 *
	 * @since 1.7.4
	 *
	 * @return bool
	 */
	private function is_dashboard() {

		global $pagenow;

		return $pagenow === 'index.php';
	}

	/**
	 * Check whether it is the form embedding admin page (Edit Post or Edit Page).
	 *
	 * @since 1.7.4
	 *
	 * @return bool
	 */
	private function is_embed_page() {

		if ( function_exists( 'get_current_screen' ) ) {
			return wpforms()->get( 'challenge' )->is_form_embed_page();
		}

		global $pagenow;

		return in_array( $pagenow, [ 'edit.php', 'post.php', 'post-new.php' ], true );
	}

	/**
	 * Load enqueues.
	 *
	 * @since 1.7.4
	 */
	public function enqueues() {

		$min = wpforms_get_min_suffix();

		// On the Dashboard and form embedding pages we should load additional scripts and styles.
		if ( $this->is_dashboard() || $this->is_embed_page() ) {
			$this->dashboard_enqueues();
		}

		wp_enqueue_script(
			'wpforms-lite-admin-education-lite-connect',
			WPFORMS_PLUGIN_URL . "assets/lite/js/admin/education/lite-connect{$min}.js",
			[ 'jquery' ],
			WPFORMS_VERSION,
			true
		);

		wp_localize_script(
			'wpforms-lite-admin-education-lite-connect',
			'wpforms_education_lite_connect',
			$this->get_js_strings()
		);
	}

	/**
	 * Dashboard enqueues.
	 *
	 * @since 1.7.4
	 */
	private function dashboard_enqueues() {

		$min = wpforms_get_min_suffix();

		// jQuery confirm.
		wp_enqueue_script(
			'jquery-confirm',
			WPFORMS_PLUGIN_URL . 'assets/lib/jquery.confirm/jquery-confirm.min.js',
			[ 'jquery' ],
			'3.3.4',
			true
		);

		wp_enqueue_style(
			'jquery-confirm',
			WPFORMS_PLUGIN_URL . 'assets/lib/jquery.confirm/jquery-confirm.min.css',
			[],
			'3.3.4'
		);

		// FontAwesome.
		wp_enqueue_style(
			'wpforms-font-awesome',
			WPFORMS_PLUGIN_URL . 'assets/lib/font-awesome/font-awesome.min.css',
			null,
			'4.7.0'
		);

		// Dashboard Education styles.
		wp_enqueue_style(
			'wpforms-lite-admin-education-lite-connect',
			WPFORMS_PLUGIN_URL . "assets/lite/css/dashboard-education{$min}.css",
			[],
			WPFORMS_VERSION
		);
	}

	/**
	 * Confirmation modal template.
	 *
	 * @since 1.7.4
	 */
	public function modal_template() {

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render( 'education/lite-connect-modal' );
	}

	/**
	 * Get localize strings.
	 *
	 * @since 1.7.4
	 *
	 * @return array
	 */
	private function get_js_strings() {

		return [
			'ajax_url'      => admin_url( 'admin-ajax.php' ),
			'nonce'         => wp_create_nonce( 'wpforms-lite-connect-toggle' ),
			'is_enabled'    => $this->is_enabled,
			'enable_modal'  => [
				'confirm' => esc_html__( 'Enable Entry Backups', 'wpforms-lite' ),
				'cancel'  => esc_html__( 'No Thanks', 'wpforms-lite' ),
			],
			'disable_modal' => [
				'title'   => esc_html__( 'Are you sure?', 'wpforms-lite' ),
				'content' => esc_html__( 'If you disable Lite Connect, you will no longer be able to restore your entries when you upgrade to WPForms Pro.', 'wpforms-lite' ),
				'confirm' => esc_html__( 'Disable Entry Backups', 'wpforms-lite' ),
				'cancel'  => esc_html__( 'Cancel', 'wpforms-lite' ),
			],
			'update_result' => [
				'enabled_title'  => esc_html__( 'Entry Backups Enabled', 'wpforms-lite' ),
				'enabled'        => esc_html__( 'Awesome! If you decide to upgrade to WPForms Pro, you can restore your entries and will have instant access to reports.', 'wpforms-lite' ),
				'disabled_title' => esc_html__( 'Entry Backups Disabled', 'wpforms-lite' ),
				'disabled'       => esc_html__( 'Form Entry Backups were successfully disabled.', 'wpforms-lite' ),
				'error_title'    => esc_html__( 'Error', 'wpforms-lite' ),
				'error'          => esc_html__( 'Unfortunately, the error occurs while updating Form Entry Backups setting. Please try again later.', 'wpforms-lite' ),
				'close'          => esc_html__( 'Close', 'wpforms-lite' ),
			],
		];
	}

	/**
	 * Generate Lite Connect entries information.
	 *
	 * @since 1.7.4
	 *
	 * @return string
	 */
	private function get_lite_connect_entries_since_info() {

		$entries_count = LiteConnectIntegration::get_new_entries_count();
		$enabled_since = LiteConnectIntegration::get_enabled_since();

		$string = sprintf(
			esc_html( /* translators: %d - Backed up entries count. */
				_n(
					'%d entry backed up',
					'%d entries backed up',
					$entries_count,
					'wpforms-lite'
				)
			),
			absint( $entries_count )
		);

		if ( ! empty( $enabled_since ) ) {
			$string .= ' ' . sprintf(
				/* translators: %s - Time when Lite Connect was enabled. */
				esc_html__( 'since %s', 'wpforms-lite' ),
				esc_html( date_i18n( 'M j, Y', $enabled_since + get_option( 'gmt_offset' ) * 3600 ) )
			);
		}

		return $string;
	}

	/**
	 * Add content before the Chart block in the Dashboard Widget.
	 *
	 * @since 1.7.4
	 *
	 * @param string $content Content.
	 *
	 * @return string
	 */
	public function dashboard_widget_before_content( $content ) {

		$toggle = wpforms_panel_field_toggle_control(
			[
				'control-class' => 'wpforms-setting-lite-connect-auto-save-toggle',
			],
			'wpforms-setting-lite-connect-enabled',
			'',
			esc_html__( 'Enable Form Entry Backups', 'wpforms-lite' ),
			$this->is_enabled,
			'disabled'
		);

		return wpforms_render(
			'education/admin/lite-connect/dashboard-widget-before',
			[
				'toggle'             => $toggle,
				'is_enabled'         => $this->is_enabled,
				'entries_since_info' => $this->get_lite_connect_entries_since_info(),
			],
			true
		);
	}

	/**
	 * Add top bar before the toolbar in the Form Builder.
	 *
	 * @since 1.7.4
	 *
	 * @param string $content Content before the toolbar. Defaults to empty string.
	 *
	 * @return string
	 */
	public function top_bar_content( $content ) {

		if ( $this->is_enabled ) {
			return $content;
		}

		$dismissed = get_user_meta( get_current_user_id(), 'wpforms_dismissed', true );

		// Skip when top bar is dismissed.
		if ( ! empty( $dismissed['edu-builder-lite-connect-top-bar'] ) ) {
			return $content;
		}

		$toggle = wpforms_panel_field_toggle_control(
			[
				'control-class' => 'wpforms-setting-lite-connect-auto-save-toggle',
			],
			'wpforms-setting-lite-connect-enabled',
			'',
			esc_html__( 'Enable Form Entry Backups for Free', 'wpforms-lite' ),
			$this->is_enabled,
			'disabled'
		);

		return wpforms_render(
			'education/builder/lite-connect/top-bar',
			[
				'toggle'     => $toggle,
				'is_enabled' => $this->is_enabled,
			],
			true
		);
	}

	/**
	 * Challenge Congrats popup footer.
	 *
	 * @since 1.7.4
	 *
	 * @param string $content Footer content.
	 *
	 * @return string
	 */
	public function challenge_popup_footer_content( $content ) {

		if ( $this->is_enabled ) {
			return $content;
		}

		$toggle = wpforms_panel_field_toggle_control(
			[
				'control-class' => 'wpforms-setting-lite-connect-auto-save-toggle',
			],
			'wpforms-setting-lite-connect-enabled',
			'',
			esc_html__( 'Enable Form Entry Backups for Free', 'wpforms-lite' ),
			$this->is_enabled,
			'disabled'
		);

		return wpforms_render(
			'education/admin/lite-connect/challenge-popup-footer',
			[
				'toggle'     => $toggle,
				'is_enabled' => $this->is_enabled,
			],
			true
		);
	}

	/**
	 * AJAX action: update Lite Connect Enabled setting.
	 *
	 * @since 1.7.4
	 */
	public function ajax_update_lite_connect_enabled_setting() {

		// Run a security check.
		check_ajax_referer( 'wpforms-lite-connect-toggle', 'nonce' );

		// Check for permissions.
		if ( ! wpforms_current_user_can( wpforms_get_capability_manage_options() ) ) {
			wp_send_json_error( esc_html__( 'You do not have permission.', 'wpforms-lite' ) );
		}

		$slug = LiteConnectClass::SETTINGS_SLUG;

		$settings          = get_option( 'wpforms_settings', [] );
		$settings[ $slug ] = ! empty( $_POST['value'] );

		wpforms_update_settings( $settings );

		if ( ! $settings[ $slug ] ) {
			wp_send_json_success( '' );
		}

		// Reset generate key attempts counter.
		update_option( API::GENERATE_KEY_ATTEMPT_COUNTER_OPTION, 0 );

		// We have to start requesting site keys in ajax, turning on the LC functionality.
		// First, the request to the API server will be sent.
		// Second, the server will respond to our callback URL /wpforms/auth/key/nonce, and the site key will be stored in the DB.
		// Third, we have to get access via a separate HTTP request.
		( new LiteConnectIntegration() )->update_keys(); // First request here.

		wp_send_json_success( $this->get_lite_connect_entries_since_info() );
	}
}
