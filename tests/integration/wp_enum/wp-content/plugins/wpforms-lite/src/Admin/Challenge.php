<?php

namespace WPForms\Admin;

/**
 * Challenge and guide a user to set up a first form once WPForms is installed.
 *
 * @since 1.5.0
 * @since 1.6.2 Challenge v2
 */
class Challenge {

	/**
	 * Number of minutes to complete the Challenge.
	 *
	 * @since 1.5.0
	 *
	 * @var int
	 */
	protected $minutes = 5;

	/**
	 * Initialize.
	 *
	 * @since 1.6.2
	 */
	public function init() {

		if ( current_user_can( wpforms_get_capability_manage_options() ) ) {
			$this->hooks();
		}
	}

	/**
	 * Hooks.
	 *
	 * @since 1.5.0
	 */
	public function hooks() {

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
		add_action( 'wpforms_builder_init', [ $this, 'init_challenge' ] );
		add_action( 'admin_footer', [ $this, 'challenge_html' ] );
		add_action( 'wpforms_welcome_intro_after', [ $this, 'welcome_html' ] );

		add_action( 'wp_ajax_wpforms_challenge_save_option', [ $this, 'save_challenge_option_ajax' ] );
		add_action( 'wp_ajax_wpforms_challenge_send_contact_form', [ $this, 'send_contact_form_ajax' ] );
	}

	/**
	 * Check if the current page is related to Challenge.
	 *
	 * @since 1.5.0
	 */
	public function is_challenge_page() {

		return wpforms_is_admin_page() ||
			   $this->is_builder_page() ||
			   $this->is_form_embed_page();
	}

	/**
	 * Check if the current page is a forms builder page related to Challenge.
	 *
	 * @since 1.5.0
	 *
	 * @return bool
	 */
	public function is_builder_page() {

		if ( ! wpforms_is_admin_page( 'builder' ) ) {
			return false;
		}

		if ( ! $this->challenge_active() && ! $this->challenge_inited() ) {
			return false;
		}

		$step    = (int) $this->get_challenge_option( 'step' );
		$form_id = (int) $this->get_challenge_option( 'form_id' );

		if ( $form_id && $step < 2 ) {
			return false;
		}

		$current_form_id = isset( $_GET['form_id'] ) ? (int) $_GET['form_id'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$is_new_form     = isset( $_GET['newform'] ) ? (int) $_GET['newform'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( $is_new_form && $step !== 2 ) {
			return false;
		}

		if ( ! $is_new_form && $form_id !== $current_form_id && $step >= 2 ) {

			// In case if user skipped the Challenge by closing the browser window or exiting the builder,
			// we need to set the previous Challenge as `canceled`.
			// Otherwise, the Form Embed Wizard will think that the Challenge is active.
			$this->set_challenge_option(
				[
					'status'            => 'skipped',
					'finished_date_gmt' => current_time( 'mysql', true ),
				]
			);

			return false;
		}

		return true;
	}

	/**
	 * Check if the current page is a form embed page edit related to Challenge.
	 *
	 * @since 1.5.0
	 *
	 * @return bool
	 */
	public function is_form_embed_page() { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		if ( ! function_exists( 'get_current_screen' ) || ! is_admin() || ! is_user_logged_in() ) {
			return false;
		}

		$screen = get_current_screen();

		if ( ! isset( $screen->id ) || $screen->id !== 'page' || ! $this->challenge_active() ) {
			return false;
		}

		$step = $this->get_challenge_option( 'step' );

		if ( ! in_array( $step, [ 3, 4, 5 ], true ) ) {
			return false;
		}

		$embed_page    = $this->get_challenge_option( 'embed_page' );
		$is_embed_page = false;

		if ( isset( $screen->action ) && $screen->action === 'add' && $embed_page === 0 ) {
			$is_embed_page = true;
		}

		if ( isset( $_GET['post'] ) && $embed_page === (int) $_GET['post'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$is_embed_page = true;
		}

		if ( $is_embed_page && $step < 4 ) {
			$this->set_challenge_option( [ 'step' => 4 ] );
		}

		return $is_embed_page;
	}

	/**
	 * Load scripts and styles.
	 *
	 * @since 1.5.0
	 */
	public function enqueue_scripts() {

		if ( ! $this->challenge_can_start() && ! $this->challenge_active() ) {
			return;
		}

		$min = wpforms_get_min_suffix();

		if ( $this->is_challenge_page() ) {

			wp_enqueue_style(
				'wpforms-challenge',
				WPFORMS_PLUGIN_URL . "assets/css/challenge{$min}.css",
				[],
				WPFORMS_VERSION
			);

			wp_enqueue_script(
				'wpforms-challenge-admin',
				WPFORMS_PLUGIN_URL . "assets/js/components/admin/challenge/challenge-admin{$min}.js",
				[ 'jquery' ],
				WPFORMS_VERSION,
				true
			);

			wp_localize_script(
				'wpforms-challenge-admin',
				'wpforms_challenge_admin',
				[
					'nonce'        => wp_create_nonce( 'wpforms_challenge_ajax_nonce' ),
					'minutes_left' => absint( $this->minutes ),
					'option'       => $this->get_challenge_option(),
				]
			);
		}

		if ( $this->is_builder_page() || $this->is_form_embed_page() ) {

			wp_enqueue_style(
				'tooltipster',
				WPFORMS_PLUGIN_URL . 'assets/lib/jquery.tooltipster/jquery.tooltipster.min.css',
				null,
				'4.2.6'
			);

			wp_enqueue_script(
				'tooltipster',
				WPFORMS_PLUGIN_URL . 'assets/lib/jquery.tooltipster/jquery.tooltipster.min.js',
				[ 'jquery' ],
				'4.2.6',
				true
			);

			wp_enqueue_script(
				'wpforms-challenge-core',
				WPFORMS_PLUGIN_URL . "assets/js/components/admin/challenge/challenge-core{$min}.js",
				[ 'jquery', 'tooltipster', 'wpforms-challenge-admin' ],
				WPFORMS_VERSION,
				true
			);
		}

		if ( $this->is_builder_page() ) {

			wp_enqueue_script(
				'wpforms-challenge-builder',
				WPFORMS_PLUGIN_URL . "assets/js/components/admin/challenge/challenge-builder{$min}.js",
				[ 'jquery', 'tooltipster', 'wpforms-challenge-core', 'wpforms-builder' ],
				WPFORMS_VERSION,
				true
			);
		}

		if ( $this->is_form_embed_page() ) {

			wp_enqueue_style(
				'wpforms-font-awesome',
				WPFORMS_PLUGIN_URL . 'assets/lib/font-awesome/font-awesome.min.css',
				null,
				'4.7.0'
			);

			wp_enqueue_script(
				'wpforms-challenge-embed',
				WPFORMS_PLUGIN_URL . "assets/js/components/admin/challenge/challenge-embed{$min}.js",
				[ 'jquery', 'tooltipster', 'wpforms-challenge-core' ],
				WPFORMS_VERSION,
				true
			);
		}
	}

	/**
	 * Get 'wpforms_challenge' option schema.
	 *
	 * @since 1.5.0
	 *
	 * @return array
	 */
	public function get_challenge_option_schema() {

		return [
			'status'              => '',
			'step'                => 0,
			'user_id'             => get_current_user_id(),
			'form_id'             => 0,
			'embed_page'          => 0,
			'embed_page_title'    => '',
			'started_date_gmt'    => '',
			'finished_date_gmt'   => '',
			'seconds_spent'       => 0,
			'seconds_left'        => 0,
			'feedback_sent'       => false,
			'feedback_contact_me' => false,
			'window_closed'       => '',
		];
	}

	/**
	 * Get Challenge parameter(s) from Challenge option.
	 *
	 * @since 1.5.0
	 *
	 * @param array|string|null $query Query using 'wpforms_challenge' schema keys.
	 *
	 * @return array|mixed
	 */
	public function get_challenge_option( $query = null ) {

		if ( ! $query ) {
			return get_option( 'wpforms_challenge' );
		}

		$return_single = false;

		if ( ! is_array( $query ) ) {
			$return_single = true;
			$query         = [ $query ];
		}

		$query = array_flip( $query );

		$option = get_option( 'wpforms_challenge' );

		if ( ! $option || ! is_array( $option ) ) {
			return array_intersect_key( $this->get_challenge_option_schema(), $query );
		}

		$result = array_intersect_key( $option, $query );

		if ( $return_single ) {
			$result = reset( $result );
		}

		return $result;
	}

	/**
	 * Set Challenge parameter(s) to Challenge option.
	 *
	 * @since 1.5.0
	 *
	 * @param array $query Query using 'wpforms_challenge' schema keys.
	 */
	public function set_challenge_option( $query ) {

		if ( empty( $query ) || ! is_array( $query ) ) {
			return;
		}

		$schema  = $this->get_challenge_option_schema();
		$replace = array_intersect_key( $query, $schema );

		if ( ! $replace ) {
			return;
		}

		// Validate and sanitize the data.
		foreach ( $replace as $key => $value ) {
			if ( in_array( $key, [ 'step', 'user_id', 'form_id', 'embed_page', 'seconds_spent', 'seconds_left' ], true ) ) {
				$replace[ $key ] = absint( $value );

				continue;
			}
			if ( in_array( $key, [ 'feedback_sent', 'feedback_contact_me' ], true ) ) {
				$replace[ $key ] = wp_validate_boolean( $value );

				continue;
			}
			$replace[ $key ] = sanitize_text_field( $value );
		}

		$option = get_option( 'wpforms_challenge' );
		$option = ! $option || ! is_array( $option ) ? $schema : $option;

		update_option( 'wpforms_challenge', array_merge( $option, $replace ) );
	}

	/**
	 * Check if any forms are present on a site.
	 *
	 * @since 1.5.0
	 *
	 * @retun bool
	 */
	public function website_has_forms() {

		return (bool) wpforms()->get( 'form' )->get(
			'',
			[
				'numberposts'            => 1,
				'nopaging'               => false,
				'fields'                 => 'ids',
				'no_found_rows'          => true,
				'update_post_meta_cache' => false,
				'update_post_term_cache' => false,
				'suppress_filters'       => true,
			]
		);
	}

	/**
	 * Check if Challenge was started.
	 *
	 * @since 1.5.0
	 *
	 * @return bool
	 */
	public function challenge_started() {

		return $this->get_challenge_option( 'status' ) === 'started';
	}

	/**
	 * Check if Challenge was initialized.
	 *
	 * @since 1.6.2
	 *
	 * @return bool
	 */
	public function challenge_inited() {

		return $this->get_challenge_option( 'status' ) === 'inited';
	}

	/**
	 * Check if Challenge was paused.
	 *
	 * @since 1.6.2
	 *
	 * @return bool
	 */
	public function challenge_paused() {

		return $this->get_challenge_option( 'status' ) === 'paused';
	}

	/**
	 * Check if Challenge was finished.
	 *
	 * @since 1.5.0
	 *
	 * @return bool
	 */
	public function challenge_finished() {

		$status = $this->get_challenge_option( 'status' );

		return in_array( $status, [ 'completed', 'canceled', 'skipped' ], true );
	}

	/**
	 * Check if Challenge is in progress.
	 *
	 * @since 1.5.0
	 *
	 * @return bool
	 */
	public function challenge_active() {

		return ( $this->challenge_inited() || $this->challenge_started() || $this->challenge_paused() ) && ! $this->challenge_finished();
	}

	/**
	 * Force Challenge to start.
	 *
	 * @since 1.6.2
	 *
	 * @return bool
	 */
	public function challenge_force_start() {

		/**
		 * Allow force start Challenge for testing purposes.
		 *
		 * @since 1.6.2.2
		 *
		 * @param bool $is_forced True if Challenge should be started. False by default.
		 */
		return (bool) apply_filters( 'wpforms_admin_challenge_force_start', false );
	}

	/**
	 * Check if Challenge can be started.
	 *
	 * @since 1.5.0
	 *
	 * @return bool
	 */
	public function challenge_can_start() { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		static $can_start = null;

		if ( $can_start !== null ) {
			return $can_start;
		}

		if ( $this->challenge_force_skip() ) {
			$can_start = false;
		}

		if ( $this->challenge_force_start() && ! $this->is_builder_page() && ! $this->is_form_embed_page() ) {
			$can_start = true;

			// No need to check something else in this case.
			return $can_start;
		}

		if ( $this->challenge_finished() ) {
			$can_start = false;
		}

		if ( $this->website_has_forms() ) {
			$can_start = false;
		}

		if ( $can_start === null ) {
			$can_start = true;
		}

		return $can_start;
	}

	/**
	 * Start the Challenge in Form Builder.
	 *
	 * @since 1.5.0
	 */
	public function init_challenge() {

		if ( ! $this->challenge_can_start() ) {
			return;
		}

		$this->set_challenge_option(
			wp_parse_args(
				[ 'status' => 'inited' ],
				$this->get_challenge_option_schema()
			)
		);
	}

	/**
	 * Include Challenge HTML.
	 *
	 * @since 1.5.0
	 */
	public function challenge_html() {

		if ( $this->challenge_force_skip() || ( $this->challenge_finished() && ! $this->challenge_force_start() ) ) {
			return;
		}

		if ( wpforms_is_admin_page() && ! wpforms_is_admin_page( 'getting-started' ) && $this->challenge_can_start() ) {

			// Before showing the Challenge in the `start` state we should reset the option.
			// In this way we ensure the Challenge will not appear somewhere in the builder where it is not should be.
			$this->set_challenge_option( [ 'status' => '' ] );
			$this->challenge_modal_html( 'start' );
		}

		if ( $this->is_builder_page() ) {
			$this->challenge_modal_html( 'progress' );
			$this->challenge_builder_templates_html();
		}

		if ( $this->is_form_embed_page() ) {
			$this->challenge_modal_html( 'progress' );
			$this->challenge_embed_templates_html();
		}
	}

	/**
	 * Include Challenge main modal window HTML.
	 *
	 * @since 1.5.0
	 *
	 * @param string $state State of Challenge ('start' or 'progress').
	 */
	public function challenge_modal_html( $state ) {

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'admin/challenge/modal',
			[
				'state'   => $state,
				'step'    => $this->get_challenge_option( 'step' ),
				'minutes' => $this->minutes,
			],
			true
		);
	}

	/**
	 * Include Challenge HTML templates specific to Form Builder.
	 *
	 * @since 1.5.0
	 */
	public function challenge_builder_templates_html() {

		echo wpforms_render( 'admin/challenge/builder' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Include Challenge HTML templates specific to form embed page.
	 *
	 * @since 1.5.0
	 */
	public function challenge_embed_templates_html() {

		/**
		 * Filter the content of the Challenge Congrats popup footer.
		 *
		 * @since 1.7.4
		 *
		 * @param string $footer Footer markup.
		 */
		$congrats_popup_footer = apply_filters( 'wpforms_admin_challenge_embed_template_congrats_popup_footer', '' );

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render(
			'admin/challenge/embed',
			[
				'minutes'               => $this->minutes,
				'congrats_popup_footer' => $congrats_popup_footer,
			],
			true
		);
	}

	/**
	 * Include Challenge CTA on WPForms welcome activation screen.
	 *
	 * @since 1.5.0
	 */
	public function welcome_html() {

		if ( $this->challenge_can_start() ) {
			echo wpforms_render( 'admin/challenge/welcome' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
	}

	/**
	 * Save Challenge data via AJAX.
	 *
	 * @since 1.5.0
	 */
	public function save_challenge_option_ajax() { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		check_admin_referer( 'wpforms_challenge_ajax_nonce' );

		if ( empty( $_POST['option_data'] ) ) {
			wp_send_json_error();
		}

		$schema = $this->get_challenge_option_schema();
		$query  = [];

		foreach ( $schema as $key => $value ) {
			if ( isset( $_POST['option_data'][ $key ] ) ) {
				$query[ $key ] = sanitize_text_field( wp_unslash( $_POST['option_data'][ $key ] ) );
			}
		}

		if ( empty( $query ) ) {
			wp_send_json_error();
		}

		if ( ! empty( $query['status'] ) && $query['status'] === 'started' ) {
			$query['started_date_gmt'] = current_time( 'mysql', true );
		}

		if ( ! empty( $query['status'] ) && in_array( $query['status'], [ 'completed', 'canceled', 'skipped' ], true ) ) {
			$query['finished_date_gmt'] = current_time( 'mysql', true );
		}

		if ( ! empty( $query['status'] ) && $query['status'] === 'skipped' ) {
			$query['started_date_gmt']  = current_time( 'mysql', true );
			$query['finished_date_gmt'] = $query['started_date_gmt'];
		}

		$this->set_challenge_option( $query );

		wp_send_json_success();
	}

	/**
	 * Send contact form to wpforms.com via AJAX.
	 *
	 * @since 1.5.0
	 */
	public function send_contact_form_ajax() {

		check_admin_referer( 'wpforms_challenge_ajax_nonce' );

		$url     = 'https://wpforms.com/wpforms-challenge-feedback/';
		$message = ! empty( $_POST['contact_data']['message'] ) ? sanitize_textarea_field( wp_unslash( $_POST['contact_data']['message'] ) ) : '';
		$email   = '';

		if (
			( ! empty( $_POST['contact_data']['contact_me'] ) && $_POST['contact_data']['contact_me'] === 'true' )
			|| wpforms()->is_pro()
		) {
			$current_user = wp_get_current_user();
			$email        = $current_user->user_email;
			$this->set_challenge_option( [ 'feedback_contact_me' => true ] );
		}

		if ( empty( $message ) && empty( $email ) ) {
			wp_send_json_error();
		}

		$data = [
			'body' => [
				'wpforms' => [
					'id'     => 296355,
					'submit' => 'wpforms-submit',
					'fields' => [
						2 => $message,
						3 => $email,
						4 => $this->get_challenge_license_type(),
						5 => wpforms()->version,
						6 => wpforms_get_license_key(),
					],
				],
			],
		];

		$response = wp_remote_post( $url, $data );

		if ( is_wp_error( $response ) ) {
			wp_send_json_error();
		}

		$this->set_challenge_option( [ 'feedback_sent' => true ] );
		wp_send_json_success();
	}

	/**
	 * Get the current WPForms license type as it pertains to the challenge feedback form.
	 *
	 * @since 1.8.1
	 *
	 * @return string The currently active license type.
	 */
	private function get_challenge_license_type() {

		$license_type = wpforms_get_license_type();

		if ( $license_type === false ) {
			$license_type = wpforms()->is_pro() ? 'Unknown' : 'Lite';
		}

		return ucfirst( $license_type );
	}

	/**
	 * Force WPForms Challenge to skip.
	 *
	 * @since 1.7.6
	 *
	 * @return bool
	 */
	private function challenge_force_skip() {

		return defined( 'WPFORMS_SKIP_CHALLENGE' ) && WPFORMS_SKIP_CHALLENGE;
	}
}
