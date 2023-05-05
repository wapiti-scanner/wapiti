<?php

namespace WPForms\Admin;

use WP_Post;

/**
 * Form Revisions.
 *
 * @since 1.7.3
 */
class Revisions {

	/**
	 * Current Form Builder panel view.
	 *
	 * @since 1.7.3
	 *
	 * @var string
	 */
	private $view = 'revisions';

	/**
	 * Current Form ID.
	 *
	 * @since 1.7.3
	 *
	 * @var int|false
	 */
	private $form_id = false;

	/**
	 * Current Form.
	 *
	 * @since 1.7.3
	 *
	 * @var WP_Post|null
	 */
	private $form;

	/**
	 * Current Form Revision ID.
	 *
	 * @since 1.7.3
	 *
	 * @var int|false
	 */
	private $revision_id = false;

	/**
	 * Current Form Revision.
	 *
	 * @since 1.7.3
	 *
	 * @var WP_Post|null
	 */
	private $revision;

	/**
	 * Whether revisions panel was already viewed by the user at least once.
	 *
	 * @since 1.7.3
	 *
	 * @var bool
	 */
	private $viewed;

	/**
	 * Date format to use in UI.
	 *
	 * @since 1.7.3
	 *
	 * @var string
	 */
	private $date_format = 'M j';

	/**
	 * Time format to use in UI.
	 *
	 * @since 1.7.3
	 *
	 * @var string
	 */
	private $time_format;

	/**
	 * Initialize the class if preconditions are met.
	 *
	 * @since 1.7.3
	 *
	 * @return void
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended

		if ( isset( $_REQUEST['view'] ) ) {
			$this->view = sanitize_key( $_REQUEST['view'] );
		}

		if ( isset( $_REQUEST['revision_id'] ) ) {
			$this->revision_id = absint( $_REQUEST['revision_id'] );
		}

		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		// Fetch revision, if needed.
		if ( $this->revision_id && wp_revisions_enabled( $this->form ) ) {
			$this->revision = wp_get_post_revision( $this->revision_id );
		}

		// Bail if we don't have a valid revision.
		if ( $this->revision_id && ! $this->revision instanceof WP_Post ) {
			return;
		}

		$this->time_format = get_option( 'time_format' );

		$this->hooks();
	}

	/**
	 * Whether it is allowed to load under certain conditions.
	 *
	 * - numeric, non-zero form ID provided,
	 * - the form with this ID exists and was successfully fetched,
	 * - we're in the Form Builder or processing an ajax request.
	 *
	 * @since 1.7.3
	 *
	 * @return bool
	 */
	private function allow_load() {

		if ( ! ( wpforms_is_admin_page( 'builder' ) || wp_doing_ajax() ) ) {
			return false;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$id = wp_doing_ajax() && isset( $_REQUEST['id'] ) ? absint( $_REQUEST['id'] ) : false;
		$id = isset( $_REQUEST['form_id'] ) && ! is_array( $_REQUEST['form_id'] ) ? absint( $_REQUEST['form_id'] ) : $id;
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$this->form_id = $id;
		$form_handler  = wpforms()->get( 'form' );

		if ( ! $form_handler ) {
			return false;
		}

		$this->form = $form_handler->get( $this->form_id );

		return $this->form_id && $this->form instanceof WP_Post;
	}

	/**
	 * Hook into WordPress lifecycle.
	 *
	 * @since 1.7.3
	 */
	private function hooks() {

		// Restore a revision. The `admin_init` action has already fired, `current_screen` fires before headers are sent.
		add_action( 'current_screen', [ $this, 'process_restore' ] );

		// Refresh a rendered list of revisions on the frontend.
		add_action( 'wp_ajax_wpforms_get_form_revisions', [ $this, 'fetch_revisions_list' ] );

		// Mark Revisions panel as viewed when viewed for the first time. Hides the error badge.
		add_action( 'wp_ajax_wpforms_mark_panel_viewed', [ $this, 'mark_panel_viewed' ] );

		// Back-compat for forms created with revisions disabled.
		add_action( 'wpforms_builder_init', [ $this, 'maybe_create_initial_revision' ] );

		// Pass localized strings to frontend.
		add_filter( 'wpforms_builder_strings', [ $this, 'get_localized_strings' ], 10, 2 );
	}

	/**
	 * Get current revision, if available.
	 *
	 * @since 1.7.3
	 *
	 * @return WP_Post|null
	 */
	public function get_revision() {

		return $this->revision;
	}

	/**
	 * Get formatted date or time.
	 *
	 * @since 1.7.3
	 *
	 * @param string $datetime UTC datetime from the post object.
	 * @param string $part     What to return - date or time, defaults to date.
	 *
	 * @return string
	 */
	public function get_formatted_datetime( $datetime, $part = 'date' ) {

		if ( $part === 'time' ) {
			return wpforms_datetime_format( $datetime, $this->time_format, true );
		}

		return wpforms_datetime_format( $datetime, $this->date_format, true );
	}

	/**
	 * Get admin (Form Builder) base URL with additional query args.
	 *
	 * @since 1.7.3
	 *
	 * @param array $query_args Additional query args to append to the base URL.
	 *
	 * @return string
	 */
	public function get_url( $query_args = [] ) {

		$defaults = [
			'page'    => 'wpforms-builder',
			'view'    => $this->view,
			'form_id' => $this->form_id,
		];

		return add_query_arg(
			wp_parse_args( $query_args, $defaults ),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Determine if Revisions panel was previously viewed by current user.
	 *
	 * @since 1.7.3
	 *
	 * @return bool
	 */
	public function panel_viewed() {

		if ( $this->viewed === null ) {
			$this->viewed = (bool) get_user_meta( get_current_user_id(), 'wpforms_revisions_disabled_notice_dismissed', true );
		}

		return $this->viewed;
	}

	/**
	 * Mark Revisions panel as viewed by current user.
	 *
	 * @since 1.7.3
	 */
	public function mark_panel_viewed() {

		// Run a security check.
		check_ajax_referer( 'wpforms-builder', 'nonce' );

		if ( ! $this->panel_viewed() ) {
			$this->viewed = update_user_meta( get_current_user_id(), 'wpforms_revisions_disabled_notice_dismissed', true );
		}

		wp_send_json_success( [ 'updated' => $this->viewed ] );
	}

	/**
	 * Get a rendered list of all revisions.
	 *
	 * @since 1.7.3
	 *
	 * @return string
	 */
	public function render_revisions_list() {

		return wpforms_render(
			'builder/revisions/list',
			$this->prepare_template_render_arguments(),
			true
		);
	}

	/**
	 * Prepare all arguments for the template to be rendered.
	 *
	 * Note: All data is escaped in the template.
	 *
	 * @since 1.7.3
	 *
	 * @return array
	 */
	private function prepare_template_render_arguments() {

		$args = [
			'active_class'        => $this->revision ? '' : ' active',
			'current_version_url' => $this->get_url(),
			'author_id'           => $this->form->post_author,
			'revisions'           => [],
			'show_avatars'        => get_option( 'show_avatars' ),
		];

		$revisions = wp_get_post_revisions( $this->form_id );

		if ( empty( $revisions ) ) {
			return $args;
		}

		// WordPress always orders entries by `post_date` column, which contains a date and time in site's timezone configured in settings.
		// This setting is per site, not per user, and it's not expected to be changed. However, if it was changed for whatever reason,
		// the order of revisions will be incorrect. This is definitely an edge case, but we can prevent this from ever happening
		// by sorting the results using `post_date_gmt` or `post_modified_gmt`, which contains UTC date and never changes.
		uasort(
			$revisions,
			static function ( $a, $b ) {

				return strtotime( $a->post_modified_gmt ) > strtotime( $b->post_modified_gmt ) ? -1 : 1;
			}
		);

		// The first revision is always identical to the current version and should not be displayed in the list.
		$current_revision = array_shift( $revisions );

		// Display the author of current version instead of a form author.
		$args['author_id'] = $current_revision->post_author;

		foreach ( $revisions as $revision ) {
			$time_diff = sprintf( /* translators: %s - Relative time difference, e.g. "5 minutes", "12 days". */
				__( '%s ago', 'wpforms-lite' ),
				human_time_diff( strtotime( $revision->post_modified_gmt . ' +0000' ) )
			);

			$date_time = sprintf( /* translators: %1$s - date, %2$s - time when revision was created, e.g. "Dec 25 at 12:57pm". */
				__( '%1$s at %2$s', 'wpforms-lite' ),
				$this->get_formatted_datetime( $revision->post_modified_gmt ),
				$this->get_formatted_datetime( $revision->post_modified_gmt, 'time' )
			);

			$args['revisions'][] = [
				'active_class' => $this->revision && $this->revision->ID === $revision->ID ? ' active' : '',
				'url'          => $this->get_url(
					[
						'revision_id' => $revision->ID,
					]
				),
				'author_id'    => $revision->post_author,
				'time_diff'    => $time_diff,
				'date_time'    => $date_time,
			];
		}

		return $args;
	}

	/**
	 * Fetch a list of revisions via ajax.
	 *
	 * @since 1.7.3
	 */
	public function fetch_revisions_list() {

		// Run a security check.
		check_ajax_referer( 'wpforms-builder', 'nonce' );

		wp_send_json_success(
			[
				'html' => $this->render_revisions_list(),
			]
		);
	}

	/**
	 * Restore the revision (if needed) and reload the Form Builder.
	 *
	 * @since 1.7.3
	 *
	 * @return void
	 */
	public function process_restore() {

		$is_restore_request = isset( $_GET['action'] ) && $_GET['action'] === 'restore_revision';

		// Bail early.
		if (
			! $is_restore_request ||
			! $this->form_id ||
			! $this->form ||
			! $this->revision_id ||
			! $this->revision ||
			! check_admin_referer( 'restore_revision', 'wpforms_nonce' )
		) {
			return;
		}

		$restored_id = wp_restore_post_revision( $this->revision );

		if ( $restored_id ) {
			wp_safe_redirect(
				wpforms()->get( 'revisions' )->get_url(
					[
						'form_id' => $restored_id,
					]
				)
			);

			exit;
		}
	}

	/**
	 * Create initial revision for existing form.
	 *
	 * When a new form is created with revisions enabled, WordPress immediately creates first revision which is identical to the form. But when
	 * a form was created with revisions disabled, this initial revision does not exist. Revisions are saved after post update, so modifying
	 * a form that have no initial revision will update the post first, then a revision of this updated post will be saved. The version of
	 * the form that existed before this update is now gone. To avoid losing this pre-revisions state, we create this initial revision
	 * when the Form Builder loads, if needed.
	 *
	 * @since 1.7.3
	 *
	 * @return void
	 */
	public function maybe_create_initial_revision() {

		// On new form creation there's no revisions yet, bail. Also, when revisions are disabled.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['newform'] ) || ! wp_revisions_enabled( $this->form ) ) {
			return;
		}

		$revisions = wp_get_post_revisions(
			$this->form_id,
			[
				'fields'      => 'ids',
				'numberposts' => 1,
			]
		);

		if ( $revisions ) {
			return;
		}

		$initial_revision_id = wp_save_post_revision( $this->form_id );
		$initial_revision    = wp_get_post_revision( $initial_revision_id );

		// Initial revision should belong to the author of the original form.
		if ( $initial_revision->post_author !== $this->form->post_author ) {

			wp_update_post(
				[
					'ID'          => $initial_revision_id,
					'post_author' => $this->form->post_author,
				]
			);
		}
	}

	/**
	 * Pass localized strings to frontend.
	 *
	 * @since 1.7.3
	 *
	 * @param array   $strings All strings that will be passed to frontend.
	 * @param WP_Post $form    Current form object.
	 *
	 * @return array
	 */
	public function get_localized_strings( $strings, $form ) {

		$strings['revision_update_confirm'] = esc_html__( 'You’re about to save a form revision. Continuing will make this the current version.', 'wpforms-lite' );

		return $strings;
	}
}
